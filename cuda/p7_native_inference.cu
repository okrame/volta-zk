#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <numeric>
#include <string>
#include <vector>

namespace {

constexpr int L = 12, D = 768, H = 12, DH = 64, DFF = 3072, VOCAB = 50257;
constexpr int NPOS = 1024, MAX_SEQ = 150;

#define CUDA_CHECK(call) do { cudaError_t e_ = (call); if (e_ != cudaSuccess) { \
  std::cerr << #call << ": " << cudaGetErrorString(e_) << "\n"; std::exit(2); } } while (0)

struct Params {
  int ln_var_shift, shift_ln_norm, recip_den_shift, shift_qkv, shift_scores;
  int shift_softmax_norm, shift_av, shift_ffn_up, shift_embed;
  int shift_attn_proj[L], shift_ffn_down[L], seam_shifts[L - 1];
  std::vector<uint32_t> tokens;
};

struct LayerOff {
  size_t c_attn, c_attn_b, attn_proj, attn_proj_b, ffn_up, ffn_up_b;
  size_t ffn_down, ffn_down_b, ln1_g, ln1_b, ln2_g, ln2_b;
};

struct Layout {
  LayerOff layer[L];
  size_t wte, wpe, lnf_g, lnf_b, exp, gelu, ln_rsqrt, recip, count;
};

struct Reader {
  const std::vector<uint8_t>& b; size_t p = 0;
  int32_t i32() { int32_t v; std::memcpy(&v, b.data() + p, 4); p += 4; return v; }
};

std::vector<uint8_t> read_bytes(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) { std::cerr << "cannot open " << path << "\n"; std::exit(2); }
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), {});
}

Params read_params(const std::string& path) {
  const auto b = read_bytes(path);
  if (b.size() < 8 || std::string(reinterpret_cast<const char*>(b.data()), 8) !=
      std::string("VGPT2Q2\0", 8)) { std::cerr << "bad params magic\n"; std::exit(2); }
  Reader r{b, 8}; Params p{};
  p.ln_var_shift = r.i32(); r.i32(); p.shift_ln_norm = r.i32();
  r.i32(); r.i32(); p.recip_den_shift = r.i32(); r.i32(); r.i32();
  p.shift_qkv = r.i32(); p.shift_scores = r.i32();
  p.shift_softmax_norm = r.i32(); p.shift_av = r.i32();
  p.shift_ffn_up = r.i32(); p.shift_embed = r.i32();
  for (int i = 0; i < 12; ++i) r.i32();
  for (int i = 0; i < L; ++i) r.i32();
  for (int i = 0; i < L; ++i) p.shift_attn_proj[i] = r.i32();
  for (int i = 0; i < L; ++i) p.shift_ffn_down[i] = r.i32();
  for (int i = 0; i < L - 1; ++i) p.seam_shifts[i] = r.i32();
  const int n = r.i32(); p.tokens.resize(n);
  for (auto& x : p.tokens) x = static_cast<uint32_t>(r.i32());
  if (r.p != b.size()) { std::cerr << "params trailing bytes\n"; std::exit(2); }
  return p;
}

Layout make_layout() {
  Layout o{}; size_t p = 0;
  auto take = [&](size_t n) { size_t q = p; p += n; return q; };
  for (int l = 0; l < L; ++l) {
    auto& x = o.layer[l];
    x.c_attn = take(D * 3 * D); x.c_attn_b = take(3 * D);
    x.attn_proj = take(D * D); x.attn_proj_b = take(D);
    x.ffn_up = take(D * DFF); x.ffn_up_b = take(DFF);
    x.ffn_down = take(DFF * D); x.ffn_down_b = take(D);
    x.ln1_g = take(D); x.ln1_b = take(D); x.ln2_g = take(D); x.ln2_b = take(D);
  }
  o.wte = take(VOCAB * D); o.wpe = take(NPOS * D);
  o.lnf_g = take(D); o.lnf_b = take(D);
  o.exp = take(1 << 16); o.gelu = take(1 << 16);
  o.ln_rsqrt = take(1 << 16); o.recip = take(1 << 16); o.count = p;
  return o;
}

__device__ int64_t floor_div(int64_t a, int64_t b) {
  int64_t q = a / b, r = a % b; return r < 0 ? q - 1 : q;
}

__device__ int16_t req(int64_t a, int s, int* err) {
  if (s == 0) {
    if (a < INT16_MIN || a > INT16_MAX) atomicExch(err, 1);
    return static_cast<int16_t>(a);
  }
  int64_t x = a; int s2 = s;
  if (s > 16) { int s1 = s - 16; x = (x + (int64_t{1} << (s1 - 1))) >> s1; s2 = 16; }
  int64_t y = (x + (int64_t{1} << (s2 - 1))) >> s2;
  if (y < INT16_MIN || y > INT16_MAX) atomicExch(err, 1);
  return static_cast<int16_t>(y);
}

__global__ void embed_kernel(const int16_t* wte, const int16_t* wpe,
    const uint32_t* tok, int16_t* out, int rows, int pos0, int shift, int* err) {
  int z = blockIdx.x * blockDim.x + threadIdx.x;
  if (z >= rows * D) return; int r = z / D, j = z % D;
  int64_t a = static_cast<int64_t>(wte[static_cast<size_t>(tok[r]) * D + j]) +
      wpe[static_cast<size_t>(pos0 + r) * D + j];
  if (shift > 0) out[z] = req(a, shift, err);
  else { a <<= -shift; if (a < INT16_MIN || a > INT16_MAX) atomicExch(err, 1); out[z] = a; }
}

__global__ void ln_kernel(const int16_t* x, const int16_t* gain, const int16_t* bias,
    const int16_t* lut, int16_t* out, int rows, int var_shift, int shift, int* err) {
  int r0 = blockIdx.x * blockDim.x + threadIdx.x;
  if (r0 >= rows) return; const int16_t* row = x + static_cast<size_t>(r0) * D;
  int64_t sum = 0; for (int j = 0; j < D; ++j) sum += row[j];
  int64_t mean = floor_div(sum + D / 2, D), vs = 0;
  for (int j = 0; j < D; ++j) { int64_t d = row[j] - mean; vs += d * d; }
  int64_t var = floor_div(vs + D / 2, D), vin = var >> var_shift;
  if (vin < 0 || vin >= (1 << 16)) { atomicExch(err, 1); vin = 0; }
  int16_t rr = lut[vin];
  for (int j = 0; j < D; ++j) {
    int64_t a = (row[j] - mean) * static_cast<int64_t>(rr) * gain[j] +
        (static_cast<int64_t>(bias[j]) << shift);
    out[static_cast<size_t>(r0) * D + j] = req(a, shift, err);
  }
}

__global__ void gemm_kernel(const int16_t* a, const int16_t* w, const int16_t* bias,
    const int16_t* residual, int16_t* out, int m, int k, int n, int shift, int* err) {
  int z = blockIdx.x * blockDim.x + threadIdx.x;
  if (z >= m * n) return; int i = z / n, j = z % n; int64_t s = 0;
  const int16_t* ar = a + static_cast<size_t>(i) * k;
  for (int q = 0; q < k; ++q) s += static_cast<int64_t>(ar[q]) * w[static_cast<size_t>(q) * n + j];
  if (bias) s += static_cast<int64_t>(bias[j]) << shift;
  int32_t y = req(s, shift, err); if (residual) y += residual[static_cast<size_t>(i) * n + j];
  if (y < INT16_MIN || y > INT16_MAX) atomicExch(err, 1); out[z] = static_cast<int16_t>(y);
}

__global__ void qkv_kernel(const int16_t* a, const int16_t* w, const int16_t* bias,
    int16_t* q, int16_t* kc, int16_t* vc, int rows, int pos0, int shift, int* err) {
  int z = blockIdx.x * blockDim.x + threadIdx.x;
  if (z >= rows * 3 * D) return; int r = z / (3 * D), c = z % (3 * D); int64_t s = 0;
  const int16_t* ar = a + static_cast<size_t>(r) * D;
  for (int k = 0; k < D; ++k) s += static_cast<int64_t>(ar[k]) * w[static_cast<size_t>(k) * 3 * D + c];
  s += static_cast<int64_t>(bias[c]) << shift; int16_t y = req(s, shift, err);
  if (c < D) q[static_cast<size_t>(r) * D + c] = y;
  else if (c < 2 * D) kc[static_cast<size_t>(pos0 + r) * D + c - D] = y;
  else vc[static_cast<size_t>(pos0 + r) * D + c - 2 * D] = y;
}

__global__ void scores_kernel(const int16_t* q, const int16_t* kc, int16_t* scores,
    int rows, int seq, int pos0, int shift, int* err) {
  int z = blockIdx.x * blockDim.x + threadIdx.x, total = H * rows * seq;
  if (z >= total) return; int j = z % seq, u = z / seq, r = u % rows, h = u / rows;
  int qpos = pos0 + r; if (j > qpos) { scores[z] = 0; return; }
  int64_t s = 0; for (int d = 0; d < DH; ++d)
    s += static_cast<int64_t>(q[static_cast<size_t>(r) * D + h * DH + d]) *
         kc[static_cast<size_t>(j) * D + h * DH + d];
  scores[z] = req(s, shift, err);
}

__global__ void softmax_kernel(int16_t* scores, const int16_t* exp_lut,
    const int16_t* recip_lut, int rows, int seq, int pos0, int recip_shift,
    int norm_shift, int* err) {
  int u = blockIdx.x * blockDim.x + threadIdx.x;
  if (u >= H * rows) return; int r = u % rows, qpos = pos0 + r;
  int16_t* row = scores + static_cast<size_t>(u) * seq; int16_t mx = INT16_MIN;
  for (int j = 0; j <= qpos; ++j) mx = max(mx, row[j]);
  int64_t den = 0;
  for (int j = 0; j <= qpos; ++j) {
    int sp32 = static_cast<int>(row[j]) - static_cast<int>(mx);
    if (sp32 < INT16_MIN) { atomicExch(err, 1); sp32 = INT16_MIN; }
    int16_t sp = static_cast<int16_t>(sp32); int16_t e = exp_lut[static_cast<uint16_t>(sp)];
    row[j] = e; den += e;
  }
  int64_t rin = den >> recip_shift; if (rin < 0 || rin >= (1 << 16)) { atomicExch(err, 1); rin = 0; }
  int16_t rc = recip_lut[rin];
  for (int j = 0; j <= qpos; ++j) row[j] = req(static_cast<int64_t>(row[j]) * rc, norm_shift, err);
}

__global__ void av_kernel(const int16_t* weights, const int16_t* vc, int16_t* out,
    int rows, int seq, int pos0, int shift, int* err) {
  int z = blockIdx.x * blockDim.x + threadIdx.x, total = rows * D;
  if (z >= total) return; int r = z / D, c = z % D, h = c / DH, qpos = pos0 + r;
  const int16_t* wr = weights + (static_cast<size_t>(h) * rows + r) * seq; int64_t s = 0;
  for (int j = 0; j <= qpos; ++j) s += static_cast<int64_t>(wr[j]) * vc[static_cast<size_t>(j) * D + c];
  out[z] = req(s, shift, err);
}

__global__ void gelu_kernel(int16_t* x, const int16_t* lut, int n) {
  int i = blockIdx.x * blockDim.x + threadIdx.x; if (i < n) x[i] = lut[static_cast<uint16_t>(x[i])];
}

__global__ void requant_vec(int16_t* x, int n, int shift, int* err) {
  int i = blockIdx.x * blockDim.x + threadIdx.x; if (i < n) x[i] = req(x[i], shift, err);
}

__global__ void logits_kernel(const int16_t* x, const int16_t* wte, int64_t* out) {
  int v = blockIdx.x * blockDim.x + threadIdx.x; if (v >= VOCAB) return; int64_t s = 0;
  for (int j = 0; j < D; ++j) s += static_cast<int64_t>(x[j]) * wte[static_cast<size_t>(v) * D + j]; out[v] = s;
}

struct GpuModel {
  Params p; Layout o; std::vector<int16_t> blob; int16_t* db = nullptr;
  uint32_t* dtok = nullptr; int* derr = nullptr; int64_t* dlogits = nullptr;
  int16_t *x0=nullptr,*x1=nullptr,*ln=nullptr,*q=nullptr,*av=nullptr,*abo=nullptr,*up=nullptr;
  int16_t *scores=nullptr,*final_ln=nullptr,*kc=nullptr,*vc=nullptr;
  std::vector<int64_t> hlogits;

  const int16_t* w(size_t off) const { return db + off; }
  int16_t* cache(int16_t* base, int l) { return base + static_cast<size_t>(l) * MAX_SEQ * D; }

  GpuModel(const std::string& bin, const std::string& params) : p(read_params(params)), o(make_layout()) {
    auto bytes = read_bytes(bin); if (bytes.size() != o.count * 2) { std::cerr << "weight size mismatch\n"; std::exit(2); }
    blob.resize(o.count); std::memcpy(blob.data(), bytes.data(), bytes.size());
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&db), bytes.size()));
    CUDA_CHECK(cudaMemcpy(db, blob.data(), bytes.size(), cudaMemcpyHostToDevice));
    auto alloc16=[&](int16_t** z,size_t n){CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(z),n*2));};
    alloc16(&x0, MAX_SEQ*D); alloc16(&x1, MAX_SEQ*D); alloc16(&ln, MAX_SEQ*D);
    alloc16(&q, MAX_SEQ*D); alloc16(&av, MAX_SEQ*D); alloc16(&abo, MAX_SEQ*D);
    alloc16(&up, MAX_SEQ*DFF); alloc16(&scores, H*MAX_SEQ*MAX_SEQ);
    alloc16(&final_ln,D); alloc16(&kc,L*MAX_SEQ*D); alloc16(&vc,L*MAX_SEQ*D);
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&dtok), MAX_SEQ*sizeof(uint32_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&derr), sizeof(int)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&dlogits), VOCAB*sizeof(int64_t)));
    hlogits.resize(VOCAB);
  }

  ~GpuModel(){ cudaFree(db);cudaFree(dtok);cudaFree(derr);cudaFree(dlogits);cudaFree(x0);cudaFree(x1);
    cudaFree(ln);cudaFree(q);cudaFree(av);cudaFree(abo);cudaFree(up);cudaFree(scores);cudaFree(final_ln);cudaFree(kc);cudaFree(vc); }

  void check() { int e=0; CUDA_CHECK(cudaMemcpy(&e,derr,sizeof(e),cudaMemcpyDeviceToHost)); if(e){std::cerr<<"fixed-point saturation/domain error\n";std::exit(3);} }

  void layer(int l, int rows, int pos0, int16_t*& xin, int16_t*& xout) {
    const auto& z=o.layer[l]; int seq=pos0+rows, n;
    ln_kernel<<<(rows+31)/32,32>>>(xin,w(z.ln1_g),w(z.ln1_b),w(o.ln_rsqrt),ln,rows,p.ln_var_shift,p.shift_ln_norm,derr);
    n=rows*3*D; qkv_kernel<<<(n+255)/256,256>>>(ln,w(z.c_attn),w(z.c_attn_b),q,cache(kc,l),cache(vc,l),rows,pos0,p.shift_qkv,derr);
    n=H*rows*seq; scores_kernel<<<(n+255)/256,256>>>(q,cache(kc,l),scores,rows,seq,pos0,p.shift_scores,derr);
    n=H*rows; softmax_kernel<<<(n+63)/64,64>>>(scores,w(o.exp),w(o.recip),rows,seq,pos0,p.recip_den_shift,p.shift_softmax_norm,derr);
    n=rows*D; av_kernel<<<(n+255)/256,256>>>(scores,cache(vc,l),av,rows,seq,pos0,p.shift_av,derr);
    gemm_kernel<<<(n+255)/256,256>>>(av,w(z.attn_proj),w(z.attn_proj_b),xin,abo,rows,D,D,p.shift_attn_proj[l],derr);
    ln_kernel<<<(rows+31)/32,32>>>(abo,w(z.ln2_g),w(z.ln2_b),w(o.ln_rsqrt),ln,rows,p.ln_var_shift,p.shift_ln_norm,derr);
    n=rows*DFF; gemm_kernel<<<(n+255)/256,256>>>(ln,w(z.ffn_up),w(z.ffn_up_b),nullptr,up,rows,D,DFF,p.shift_ffn_up,derr);
    gelu_kernel<<<(n+255)/256,256>>>(up,w(o.gelu),n);
    n=rows*D; gemm_kernel<<<(n+255)/256,256>>>(up,w(z.ffn_down),w(z.ffn_down_b),abo,xout,rows,DFF,D,p.shift_ffn_down[l],derr);
    if(l<L-1 && p.seam_shifts[l]>0) requant_vec<<<(n+255)/256,256>>>(xout,n,p.seam_shifts[l],derr);
    std::swap(xin,xout);
  }

  uint32_t finish(int16_t* xin, int rows) {
    ln_kernel<<<1,1>>>(xin+static_cast<size_t>(rows-1)*D,w(o.lnf_g),w(o.lnf_b),w(o.ln_rsqrt),final_ln,1,p.ln_var_shift,p.shift_ln_norm,derr);
    logits_kernel<<<(VOCAB+255)/256,256>>>(final_ln,w(o.wte),dlogits);
    CUDA_CHECK(cudaMemcpy(hlogits.data(),dlogits,VOCAB*sizeof(int64_t),cudaMemcpyDeviceToHost)); check();
    return static_cast<uint32_t>(std::max_element(hlogits.begin(),hlogits.end())-hlogits.begin());
  }

  uint32_t prefill(int rows) {
    CUDA_CHECK(cudaMemset(derr,0,sizeof(int))); CUDA_CHECK(cudaMemcpy(dtok,p.tokens.data(),rows*sizeof(uint32_t),cudaMemcpyHostToDevice));
    int n=rows*D; embed_kernel<<<(n+255)/256,256>>>(w(o.wte),w(o.wpe),dtok,x0,rows,0,p.shift_embed,derr);
    int16_t* a=x0; int16_t* b=x1; for(int l=0;l<L;++l) layer(l,rows,0,a,b); return finish(a,rows);
  }

  uint32_t decode_step(uint32_t token,int pos) {
    CUDA_CHECK(cudaMemcpy(dtok,&token,sizeof(token),cudaMemcpyHostToDevice));
    embed_kernel<<<(D+255)/256,256>>>(w(o.wte),w(o.wpe),dtok,x0,1,pos,p.shift_embed,derr);
    int16_t* a=x0; int16_t* b=x1; for(int l=0;l<L;++l) layer(l,1,pos,a,b); return finish(a,1);
  }

  std::vector<uint32_t> decode50() {
    uint32_t next=prefill(100); std::vector<uint32_t> out; out.reserve(50);
    for(int i=0;i<50;++i){out.push_back(next);next=decode_step(next,100+i);} return out;
  }
};

double median(std::vector<double> x){std::sort(x.begin(),x.end());return x[x.size()/2];}

} // namespace

int main(int argc,char**argv){
  if(argc!=4){std::cerr<<"usage: p7_native_inference WEIGHTS PARAMS REPS\n";return 2;}
  int reps=std::stoi(argv[3]); GpuModel m(argv[1],argv[2]);
  uint32_t warm=m.prefill(100); auto warm_tokens=m.decode50();
  std::vector<double> ps,ds; std::vector<uint32_t> tokens; bool deterministic=true; uint32_t prefill_argmax=0;
  for(int r=0;r<reps;++r){auto t0=std::chrono::steady_clock::now();uint32_t a=m.prefill(100);auto t1=std::chrono::steady_clock::now();
    ps.push_back(std::chrono::duration<double>(t1-t0).count());prefill_argmax=a;if(a!=warm)deterministic=false;
    m.prefill(100);t0=std::chrono::steady_clock::now();auto v=m.decode50();t1=std::chrono::steady_clock::now();
    ds.push_back(std::chrono::duration<double>(t1-t0).count());if(r==0)tokens=v;else if(v!=tokens)deterministic=false;}
  cudaDeviceProp prop{};CUDA_CHECK(cudaGetDeviceProperties(&prop,0));
  std::cout<<std::setprecision(12)<<"{\n  \"prefill_s\": "<<median(ps)<<", \"decode_50_s\": "<<median(ds)
    <<",\n  \"prefill_argmax\": "<<prefill_argmax<<", \"deterministic\": "<<(deterministic?"true":"false")
    <<", \"fixed_point_errors\": false,\n  \"generated_tokens\": [";
  for(size_t i=0;i<tokens.size();++i)std::cout<<(i?", ":"")<<tokens[i];
  std::cout<<"],\n  \"parameters\": {\"prefill_tokens\": 100, \"decode_tokens\": 50, \"gpu_reps\": "<<reps
    <<", \"weights_resident\": true, \"decode_logits_d2h_per_token\": "<<VOCAB*8<<"},\n"
    <<"  \"device\": {\"name\": \""<<prop.name<<"\", \"cc\": \""<<prop.major<<'.'<<prop.minor
    <<"\", \"sm_count\": "<<prop.multiProcessorCount<<", \"global_memory_bytes\": "<<prop.totalGlobalMem<<"}\n}\n";
  return deterministic?0:1;
}

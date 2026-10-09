import ctypes,json,time
cuda=ctypes.CDLL('/usr/local/cuda/lib64/libcudart.so')
def check(code):
 if code:raise RuntimeError('CUDA status '+str(code))
def sample(label):
 stack=ctypes.c_size_t();free=ctypes.c_size_t();total=ctypes.c_size_t()
 check(cuda.cudaDeviceGetLimit(ctypes.byref(stack),ctypes.c_int(0)))
 check(cuda.cudaMemGetInfo(ctypes.byref(free),ctypes.byref(total)))
 return dict(label=label,stack_limit_bytes=stack.value,global_free_bytes=free.value,global_total_bytes=total.value,epoch=time.time())
check(cuda.cudaSetDevice(0));check(cuda.cudaFree(None));rows=[sample('default')]
check(cuda.cudaDeviceSetLimit(ctypes.c_int(0),ctypes.c_size_t(256)));rows.append(sample('requested256'))
check(cuda.cudaDeviceSetLimit(ctypes.c_int(0),ctypes.c_size_t(rows[0]['stack_limit_bytes'])));rows.append(sample('restored'))
check(cuda.cudaDeviceReset())
print(json.dumps(dict(samples=rows,scope='Separate empty CUDA context during canonical CPU setup; no C7.1 kernels executed. Global free includes the resident W of another process; this probe does not establish canonical savings or stack safety.',credit=False)))

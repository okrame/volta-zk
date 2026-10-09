import ctypes,json,time,os,pathlib
cuda=ctypes.CDLL('/usr/local/cuda/lib64/libcudart.so')
def check(code):
 if code:raise RuntimeError('CUDA status '+str(code))
check(cuda.cudaSetDevice(0));check(cuda.cudaDeviceSetLimit(ctypes.c_int(0),ctypes.c_size_t(256)))
stream=ctypes.c_void_p();allocation=ctypes.c_void_p()
check(cuda.cudaStreamCreateWithFlags(ctypes.byref(stream),ctypes.c_uint(1)))
check(cuda.cudaMalloc(ctypes.byref(allocation),ctypes.c_size_t(4096)))
check(cuda.cudaMemsetAsync(allocation,ctypes.c_int(0),ctypes.c_size_t(4096),stream))
check(cuda.cudaStreamSynchronize(stream));check(cuda.cudaFree(allocation))
stack=ctypes.c_size_t();free=ctypes.c_size_t();total=ctypes.c_size_t()
check(cuda.cudaDeviceGetLimit(ctypes.byref(stack),ctypes.c_int(0)));check(cuda.cudaMemGetInfo(ctypes.byref(free),ctypes.byref(total)))
report=dict(epoch=time.time(),environment={k:os.environ.get(k) for k in ['CUDA_DEVICE_MAX_CONNECTIONS','CUDA_DEVICE_MAX_COPY_CONNECTIONS','CUDA_SCALE_LAUNCH_QUEUES']},stack_limit_bytes=stack.value,global_free_bytes=free.value,global_total_bytes=total.value,global_used_bytes=total.value-free.value,host_status=[x for x in pathlib.Path('/proc/self/status').read_text().splitlines() if x.startswith(('VmRSS:','VmHWM:'))],scope='One fresh empty CUDA context, one nonblocking stream and a4096B memset/free. No C7.1 kernels/model; concurrentCPUcompilation only. No canonical memory or parity credit.',credit=False)
check(cuda.cudaStreamDestroy(stream));check(cuda.cudaDeviceReset());print(json.dumps(report))

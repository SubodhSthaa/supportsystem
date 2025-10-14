import torch
print(torch.cuda.is_available())       # True  ✅
print(torch.cuda.get_device_name(0))   # e.g. "NVIDIA GeForce RTX 4070"

if torch.cuda.is_available():
    print("Device name:", torch.cuda.get_device_name(0))
    x = torch.rand(3, 3).cuda()
    print("Tensor on GPU:", x)
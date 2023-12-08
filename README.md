# slice_oldJoern

## 准备源代码文件
源代码文件按照cwe_dict.json分布，一个CWE对应一个文件夹，CWE文件夹内部还可以划分为0，1，2……方便并行处理，移动文件可以用shutil模块，
上传文件可以直接往vscode中拖动即可

## 创建docker

```
docker run -itd --gpus all --name [镜像名] -v [物理机存放文件的文件夹]:/home/sagpool [镜像名]:[标签] /bin/bash  
docker run -itd --gpus all --name sagpool_wh0 -v /home/nfs/m2022-wh/data2slice:/home/sagpool tk1037/sagpool:1.0 /bin/bash
```

## 参考 slice_nvd.sh完成切片脚本  
修改其中标注需要修改的地方即可,需要注意的是脚本是在docker中运行的，所以应该对应docker中的路径

## 修改 get_points.py
主要修改get_funcid_by_filepath函数，参考filetype==NVD修改juliet获取关注点的方式，主要修改文件名和路径即可。

## 执行切片脚本  
参考指令
```
docker exec sagpool_wh0 /bin/bash -c "cd /home/sagpool/data2slice/slice_oldJoern && ./slice_nvd.sh s"
```
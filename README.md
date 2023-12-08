# slice_oldJoern
## 创建docker

```
docker run -itd --gpus all --name [镜像名] -v [物理机存放文件的文件夹]:/home/sagpool [镜像名]:[标签] /bin/bash  
docker run -itd --gpus all --name sagpool_wh0 -v /home/wanghu/SAGPool:/home/sagpool sagpool:3.0 /bin/bash
```

## 参考 slice_nvd.sh完成切片脚本  
修改其中标注需要修改的地方即可

## 执行切片脚本  
参考指令
```
docker exec sagpool_wh0 /bin/bash -c "cd /home/sagpool/data2slice/code && ./slice_nvd.sh s"
```
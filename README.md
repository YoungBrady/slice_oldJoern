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
docker exec sagpool_wh0 /bin/bash -c "cd /home/sagpool/data2slice/slice_oldJoern && ./slice_nvd.sh s 119"
```

## tmux后台
创建一个窗口
tmux new -s window_name
进入窗口
tmux a

## 并行跑
```
for num in {0..9}
do
    docker run -itd  --name sagpool_wh$num  -v  /home/wanghu/SAGPool:/home/sagpool sagpool:4.0 /bin/bash
    # docker run -itd  --name sagpool_wh$num  -v  /home/wanghu/insertVul_test:/home/sagpool sagpool:4.0 /bin/bash
    tmux new -d -s wh_$num -n window0
    # # tmux send -t wh_$num "docker exec sagpool_wh$num /bin/bash -c \"cd /home/sagpool/slice_oldJoern && ./slice_82.sh $num s\"" ENTER
    # tmux send -t wh_$num "docker exec sagpool_wh$num /bin/bash -c \"cd /home/sagpool/slice_oldJoern \"" ENTER
    # tmux kill-session -t wh_$num
    # docker restart sagpool_wh$num
    # docker rm sagpool_wh$num
    # docker stop sagpool_wh$num
# done

for num in {0..8}
do
    # tmux new -d -s wh_$num -n window0
    tmux send -t wh_$num "docker exec sagpool_wh$num /bin/bash -c \"cd /home/sagpool/data2slice/code && ./slice_nvd.sh s $num\"" ENTER
    # tmux kill-session -t wh_$num
    # docker rm sagpool_wh$num
done
```
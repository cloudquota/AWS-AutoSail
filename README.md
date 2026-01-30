基于 Go 编写的 AWS Lightsail 管理服务示例项目。

---

## 一、环境准备

### 1. 安装 Go（最新版本）

请先安装 Go 最新稳定版本（建议 ≥ 1.20）。

官方下载地址：  
https://go.dev/dl/

安装完成后，确认 Go 是否安装成功：

```bash
go version
```

---

## 二、下载项目

```bash
git clone https://github.com/cloudquota/aws-lightsail-go.git
cd aws-lightsail-go
```

---

## 三、设置账号密码环境变量

项目通过环境变量方式设置登录账号和密码：

```bash
export APP_USERNAME=admin
export APP_PASSWORD=admin123
```

> 上述环境变量仅在当前终端会话中生效  
> 如需长期生效，请写入 `~/.bashrc` 或 `~/.zshrc`

---

## 四、测试运行（前台）

用于确认程序是否可以正常启动：

```bash
go run .
```

---

## 五、后台运行

### 1. 编译程序

```bash
go build -o app
```

### 2. 后台启动

```bash
nohup ./app > app.log 2>&1 &
```

程序将在后台运行，日志输出到 `app.log`。

---

## 六、常用命令

### 查看日志

```bash
tail -f app.log
```

### 查看进程

```bash
ps aux | grep app
```

### 停止程序

```bash
pkill app
```

---

## 七、依赖问题处理

如遇到依赖缺失问题，可执行：

```bash
go mod tidy
```

---


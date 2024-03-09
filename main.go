package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/gorilla/mux"
)

var (
	imageStoragePath = "images/"
	uploadedImages   = make(map[string]string)
	mutex            = &sync.Mutex{}
	domain           string
)

func init() {
	// 从 .env 文件中加载环境变量
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
	}

	// 获取 DOMAIN 环境变量的值
	domain = os.Getenv("DOMAIN")
}

func main() {
	// 从环境变量中获取 token, port
	uploadToken := os.Getenv("UPLOAD_TOKEN")
	port := os.Getenv("PORT")

	// 如果没有设置上传 token，可以设置一个默认值
	if uploadToken == "" {
		uploadToken = "bomaosToken"
	}

	if port == "" {
		port = "3000" // 如果没有设置，使用默认端口号
	}

	// 设置路由
	r := mux.NewRouter()
	r.HandleFunc("/upload", handleUpload(uploadToken)).Methods("POST")
	r.HandleFunc("/image/{md5}", handleGetImage).Methods("GET")

	// 创建上传目录
	if err := os.MkdirAll(imageStoragePath, os.ModePerm); err != nil {
		fmt.Printf("Error creating upload directory: %s\n", err)
		return
	}

	// 启动服务
	addr := ":" + port
	fmt.Printf("Server is running on http://localhost%s\n", addr)
	http.ListenAndServe(addr, r)
}

func handleUpload(uploadToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 验证 token
		token := r.Header.Get("Authorization")
		if token != "Bearer "+uploadToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 解析表单数据
		err := r.ParseMultipartForm(10 << 20) // 限制上传文件大小为10MB
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		// 获取上传的文件
		file, handler, err := r.FormFile("image")
		if err != nil {
			http.Error(w, "Unable to get file from form", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// 计算文件的MD5哈希值
		hasher := md5.New()
		if _, err := io.Copy(hasher, file); err != nil {
			http.Error(w, "Unable to calculate MD5 hash", http.StatusInternalServerError)
			return
		}
		fileMD5 := hex.EncodeToString(hasher.Sum(nil))

		// 检查是否已存在相同的文件
		mutex.Lock()
		defer mutex.Unlock()
		if existingLink, ok := uploadedImages[fileMD5]; ok {
			// 构建 JSON 响应
			response := map[string]interface{}{
				"msg":  "Image uploaded successfully",
				"code": 0,
				"url":  existingLink,
			}

			// 将 JSON 编码并写入响应
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// 保存文件到存储路径
		filePath := filepath.Join(imageStoragePath, fileMD5+filepath.Ext(handler.Filename))
		out, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Unable to create file", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		// 重新定位文件读取位置到开头
		_, err = file.Seek(0, 0)
		if err != nil {
			http.Error(w, "Unable to reset file position", http.StatusInternalServerError)
			return
		}

		// 写入文件内容
		_, err = io.Copy(out, file)
		if err != nil {
			http.Error(w, "Unable to save file", http.StatusInternalServerError)
			return
		}

		// 保存文件信息
		uploadedImages[fileMD5] = domain + "/image/" + fileMD5 + filepath.Ext(handler.Filename)

		// 构建 JSON 响应
		response := map[string]interface{}{
			"msg":  "Image uploaded successfully",
			"code": 0,
			"url":  uploadedImages[fileMD5],
		}

		// 将 JSON 编码并写入响应
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func handleGetImage(w http.ResponseWriter, r *http.Request) {
	// 获取MD5值
	vars := mux.Vars(r)
	md5 := vars["md5"]

	// 构建文件路径
	filePath := filepath.Join(imageStoragePath, md5)

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Image not found", http.StatusNotFound)
		return
	}

	// 返回图片链接
	http.ServeFile(w, r, filePath)
}

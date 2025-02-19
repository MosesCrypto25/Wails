package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/pbkdf2"
)

//go:embed all:frontend/dist
var assets embed.FS

type App struct {
	ctx context.Context
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// EncryptFileStep 是一个带有进度更新的加密函数
func (a *App) EncryptFileStep(inputPath, outputPath, password string, progress func(float64)) error {
	// 读取文件
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}
	progress(0.1) // 10% progress

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("生成盐失败: %w", err)
	}
	progress(0.2) // 20% progress

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("生成IV失败: %w", err)
	}
	progress(0.3) // 30% progress
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("创建密码块失败: %w", err)
	}
	//progress(0.4) // 40% progress

	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	progress(0.8) // 80% progress

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer outputFile.Close()

	if _, err := outputFile.Write(salt); err != nil {
		return fmt.Errorf("写入盐失败: %w", err)
	}
	if _, err := outputFile.Write(iv); err != nil {
		return fmt.Errorf("写入IV失败: %w", err)
	}
	if _, err := outputFile.Write(ciphertext); err != nil {
		return fmt.Errorf("写入加密数据失败: %w", err)
	}
	progress(1.0) // 100% progress

	return nil
}

func (a *App) DecryptFile(inputPath, outputPath, password string) error {
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("读取加密文件失败: %w", err)
	}

	if len(ciphertext) < 32 {
		return errors.New("文件格式无效")
	}

	salt := ciphertext[:16]
	iv := ciphertext[16:32]
	ciphertext = ciphertext[32:]

	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("创建密码块失败: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return errors.New("加密数据长度无效")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return fmt.Errorf("解密失败: %w", err)
	}

	if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
		return fmt.Errorf("写入解密文件失败: %w", err)
	}

	return nil
}

func (a *App) SelectFile() string {
	selection, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择文件",
	})
	if err != nil {
		return ""
	}
	return selection
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("空数据")
	}
	padding := int(data[len(data)-1])
	if padding < 1 || padding > len(data) {
		return nil, errors.New("填充大小无效")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("填充内容无效")
		}
	}
	return data[:len(data)-padding], nil
}

func main() {

	app := NewApp()
	err := wails.Run(&options.App{
		Title:  "文件加密工具",
		Width:  500,
		Height: 400,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}

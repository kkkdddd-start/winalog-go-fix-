//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/collectors"
)

func main() {
	output := flag.String("o", "winalog_collect_"+time.Now().Format("20060102_150405")+".zip", "输出文件路径 (.zip)")
	workers := flag.Int("workers", 4, "并行工作线程数")
	compress := flag.Bool("compress", true, "打包为ZIP")
	calculateHash := flag.Bool("hash", true, "计算文件哈希")
	noLogs := flag.Bool("no-logs", false, "跳过事件日志采集")
	noProcesses := flag.Bool("no-processes", false, "跳过进程信息采集")
	noDLLs := flag.Bool("no-dlls", false, "跳过进程DLL采集")
	noDrivers := flag.Bool("no-drivers", false, "跳过驱动信息采集")
	noNetwork := flag.Bool("no-network", false, "跳过网络连接采集")
	noUsers := flag.Bool("no-users", false, "跳过本地用户采集")
	noSystemInfo := flag.Bool("no-sysinfo", false, "跳过系统信息采集")
	flag.Parse()

	fmt.Println("=== Winalog Collector (Standalone) ===")
	fmt.Printf("输出文件: %s\n", *output)
	fmt.Printf("并行线程: %d\n", *workers)
	fmt.Println()

	ctx := context.Background()

	opts := collectors.CollectOptions{
		Workers:            *workers,
		OutputPath:         *output,
		Compress:           *compress,
		CalculateHash:      *calculateHash,
		IncludeLogs:        !*noLogs,
		IncludePrefetch:    false,
		IncludeRegistry:    false,
		IncludeStartup:     false,
		IncludeSystemInfo:  !*noSystemInfo,
		IncludeShimCache:   false,
		IncludeAmcache:     false,
		IncludeUserassist:  false,
		IncludeUSNJournal:  false,
		IncludeTasks:       false,
		IncludeNetwork:     !*noNetwork,
		IncludeProcessSig:  !*noProcesses,
		IncludeProcessDLLs: !*noDLLs,
		IncludeDrivers:     !*noDrivers,
		IncludeUsers:       !*noUsers,
	}

	fmt.Println("开始采集...")
	fmt.Println()

	result, err := collectors.RunOneClickCollection(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "采集失败: %v\n", err)
		os.Exit(1)
	}

	oneClickResult, ok := result.(*collectors.OneClickResult)
	if !ok {
		fmt.Fprintf(os.Stderr, "返回结果类型错误\n")
		os.Exit(1)
	}

	if oneClickResult.Success {
		fmt.Println()
		fmt.Println("========================================")
		fmt.Println("  采集完成!")
		fmt.Printf("  输出文件: %s\n", oneClickResult.OutputPath)
		fmt.Printf("  耗时: %v\n", oneClickResult.Duration.Round(time.Second))
		fmt.Printf("  采集项目: %d 成功, %d 失败\n",
			oneClickResult.Summary.TotalCollected,
			oneClickResult.Summary.TotalFailed)
		fmt.Println("========================================")
	} else {
		fmt.Println()
		fmt.Println("采集完成，但有错误:")
		for _, item := range oneClickResult.Summary.CollectedItems {
			status := "成功"
			if item.Error != "" {
				status = "失败: " + item.Error
			}
			fmt.Printf("  [%s] %s\n", status, item.DisplayName)
		}
		for _, item := range oneClickResult.Summary.FailedItems {
			fmt.Printf("  [失败: %s] %s\n", item.Error, item.DisplayName)
		}
		os.Exit(1)
	}
}

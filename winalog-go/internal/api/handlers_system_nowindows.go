//go:build !windows

package api

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetUsers godoc
// @Summary 获取用户列表
// @Description 返回系统本地用户列表(非Windows)
// @Tags system
// @Produce json
// @Success 200 {object} UserResponse
// @Router /api/system/users [get]
func (h *SystemHandler) GetUsers(c *gin.Context) {
	log.Printf("[INFO] GetUsers called - not supported on this platform")

	c.JSON(http.StatusOK, UserResponse{
		Users: []*UserInfo{},
		Total: 0,
	})
}

// GetScheduledTasks godoc
// @Summary 获取计划任务列表
// @Description 返回系统计划任务列表(非Windows)
// @Tags system
// @Produce json
// @Success 200 {object} TaskResponse
// @Router /api/system/tasks [get]
func (h *SystemHandler) GetScheduledTasks(c *gin.Context) {
	log.Printf("[INFO] GetScheduledTasks called - not supported on this platform")

	c.JSON(http.StatusOK, TaskResponse{
		Tasks: []*TaskInfo{},
		Total: 0,
	})
}

func getWindowsSystemMemory() (totalGB float64, freeGB float64) {
	return 0, 0
}

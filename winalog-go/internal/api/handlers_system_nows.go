//go:build !windows

package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetProcesses godoc
// @Summary 获取进程列表
// @Description 返回系统进程列表(非Windows)
// @Tags system
// @Produce json
// @Success 200 {object} ProcessResponse
// @Router /api/system/processes [get]
func (h *SystemHandler) GetProcesses(c *gin.Context) {
	c.JSON(http.StatusOK, ProcessResponse{
		Processes: []*ProcessInfo{},
		Total:     0,
	})
}

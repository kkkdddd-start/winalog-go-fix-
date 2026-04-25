//go:build !windows

package api

import "github.com/gin-gonic/gin"

func (h *SystemHandler) ExportProcesses(c *gin.Context)        {}
func (h *SystemHandler) ExportNetworkConnections(c *gin.Context) {}
func (h *SystemHandler) ExportLoadedDLLs(c *gin.Context)         {}
func (h *SystemHandler) ExportEnvironmentVariables(c *gin.Context) {}
func (h *SystemHandler) ExportDrivers(c *gin.Context)           {}
func (h *SystemHandler) ExportUsers(c *gin.Context)             {}
func (h *SystemHandler) ExportRegistryPersistence(c *gin.Context) {}
func (h *SystemHandler) ExportScheduledTasks(c *gin.Context)    {}

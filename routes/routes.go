package routers

import (
	controllers "log-in-go/controller"
	"log-in-go/middleware"

	"github.com/gin-gonic/gin"
)

func GetRoute(r *gin.Engine) {
	r.POST("/api/signup", controllers.Signup)
	r.POST("/api/login", controllers.Login)

	r.Use(middleware.RequireAuth)
	r.POST("/api/logout", controllers.Logout)
	userRouter := r.Group("/api/users")
	{
		userRouter.GET("/", controllers.GetUsers)
		userRouter.PUT("/:id/update", controllers.UpdateUser)
		userRouter.DELETE("/:id/delete", controllers.DeleteUser)
	}

}

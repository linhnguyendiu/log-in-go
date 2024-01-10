package db

import (
	"fmt"
	"log-in-go/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

var err error

func InitialMigration() {
	DB, err = gorm.Open(mysql.Open(ConnectionString), &gorm.Config{})
	if err != nil {
		fmt.Println(err.Error())
		panic("Can't connect to DB!")
	} else {
		fmt.Println("Connect to database sucessfull")
	}

	DB.AutoMigrate(&models.User{})
}

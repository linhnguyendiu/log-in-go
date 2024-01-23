package db

import (
	"fmt"
	"log-in-go/models"

	"github.com/go-redis/redis/v8"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	DB       *gorm.DB
	RedisCli *redis.Client
)

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
	InitRedis()
}

func InitRedis() {
	RedisCli = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	fmt.Println(RedisCli)
}

package controllers

import (
	"context"
	"fmt"
	"log"
	"log-in-go/db"
	format_errors "log-in-go/format-errors"
	"log-in-go/models"
	"log-in-go/pagination"
	"log-in-go/validations"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	var userInput struct {
		Name     string `json:"name" binding:"required,min=2,max=50"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&userInput); err != nil {
		if errs, ok := err.(validator.ValidationErrors); ok {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"validations": validations.FormatValidationErrors(errs),
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if validations.IsUniqueValue("users", "email", userInput.Email) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"validations": map[string]interface{}{
				"Email": "The email is already exist!",
			},
		})
		return
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(userInput.Password), 10)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash password",
		})

		return
	}

	user := models.User{
		Name:     userInput.Name,
		Email:    userInput.Email,
		Password: string(hashPassword),
	}

	result := db.DB.Create(&user)

	if result.Error != nil {
		format_errors.InternalServerError(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

func Login(c *gin.Context) {
	var userInput struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if c.ShouldBindJSON(&userInput) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Request failed",
		})

		return
	}

	attemptsKey := fmt.Sprintf("login_attempts:%s", userInput.Email)
	var attempts int64

	lockedKey := fmt.Sprintf("account_locked:%s", userInput.Email)
	isLocked, err := db.RedisCli.Exists(context.Background(), lockedKey).Result()
	if err != nil {
		log.Printf("Error checking if the account is locked: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	if isLocked > 0 {
		isLocked = 0
		lockTimestamp, err := db.RedisCli.Get(context.Background(), lockedKey).Result()
		if err != nil {
			log.Printf("Error getting lock timestamp from Redis: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		lockTime, err := time.Parse(time.RFC3339, lockTimestamp)
		if err != nil {
			log.Printf("Error parsing lock timestamp: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		// If 1 minute has not passed since the lock, return an appropriate response
		if time.Since(lockTime) >= time.Minute {
			attempts = 0
			isLocked = 0
			err := db.RedisCli.Del(context.Background(), lockedKey, attemptsKey).Err()
			if err != nil {
				log.Printf("Error resetting account lock and login attempts in Redis: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
				return
			}
		} else {
			c.JSON(http.StatusLocked, gin.H{"error": "Account locked. Please try again later.", "Time-still": time.Since(lockTime)})
			return
		}
	}

	var user models.User
	db.DB.First(&user, "email = ?", userInput.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})

		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userInput.Password))
	if err != nil {
		// Increase login attempts in Redis
		attemptsKey = fmt.Sprintf("login_attempts:%s", userInput.Email)
		attempts, err = db.RedisCli.Incr(context.Background(), attemptsKey).Result()
		if err != nil {
			log.Printf("Error increasing login attempts in Redis: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		if attempts > 5 {
			isLocked = 0
			attempts = 0
			lockTimestamp := time.Now().UTC().Format(time.RFC3339)
			err = db.RedisCli.Set(context.Background(), lockedKey, lockTimestamp, 1*time.Minute).Err()
			if err != nil {
				log.Printf("Error locking the account in Redis: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
				return
			}

			c.JSON(http.StatusLocked, gin.H{"error": "Your account has been locked, entered the wrong password more than 5 times"})
			return
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

	}
	// Reset login attempts in Redis upon successful login
	isLocked = 0
	attempts = 0
	err = db.RedisCli.Del(context.Background(), fmt.Sprintf("login_attempts:%s", userInput.Email)).Err()
	if err != nil {
		log.Printf("Error resetting login attempts in Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	// Set expiry time and send the token back
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func Logout(c *gin.Context) {
	c.SetCookie("Authorization", "", 0, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"successMessage": "Logout successful",
	})
}

// Get all users
func GetUsers(c *gin.Context) {
	var users []models.User

	pageStr := c.DefaultQuery("page", "1")
	page, _ := strconv.Atoi(pageStr)

	perPageStr := c.DefaultQuery("perPage", "5")
	perPage, _ := strconv.Atoi(perPageStr)

	result, err := pagination.Paginate(db.DB, page, perPage, nil, &users)
	if err != nil {
		format_errors.InternalServerError(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"result": result,
	})
}

// Update a user
func UpdateUser(c *gin.Context) {
	id := c.Param("id")

	var userInput struct {
		Name  string `json:"name" binding:"required,min=2,max=50"`
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&userInput); err != nil {
		if errs, ok := err.(validator.ValidationErrors); ok {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"validations": validations.FormatValidationErrors(errs),
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	var user models.User
	result := db.DB.First(&user, id)

	if err := result.Error; err != nil {
		format_errors.RecordNotFound(c, err)
		return
	}

	if user.Email != userInput.Email && validations.IsUniqueValue("users", "email", userInput.Email) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"validations": map[string]interface{}{
				"Email": "The email is already exist!",
			},
		})
		return
	}

	updateUser := models.User{
		Name:  userInput.Name,
		Email: userInput.Email,
	}

	result = db.DB.Model(&user).Updates(&updateUser)

	if result.Error != nil {
		format_errors.InternalServerError(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

// Delete a user by id
func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	var user models.User

	result := db.DB.First(&user, id)

	if err := result.Error; err != nil {
		format_errors.RecordNotFound(c, err)
		return
	}

	db.DB.Delete(&user)

	err := db.DB.Delete(&user, id).Error

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Could not delete", "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "The user has been deleted successfully",
	})
}

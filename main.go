package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-playground/validator"
	"github.com/go-redis/redis/v8"
	"github.com/go-redsync/redsync/v4"
	"github.com/go-redsync/redsync/v4/redis/goredis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	db          *gorm.DB
	redisClient *redis.Client
	rs          *redsync.Redsync
	logger      zerolog.Logger
)

type User struct {
	gorm.Model
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" gorm:"unique" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UpdateUserRequest struct {
	Name  string `json:"name"`
	Email string `json:"email" validate:"email"`
}

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}

type CustomError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var requestGroup singleflight.Group

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file")
	}

	initLogger()
	initDb()
	initRedis()
}

func initLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
}

func initDb() {
	dsn := os.Getenv("DATABASE_URL")
	var err error
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database")
	}
	db.AutoMigrate(&User{})
}

func initRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("DRAGONFLY_HOST"),
		Password: os.Getenv("DRAGONFLY_PORT"),
	})
	pool := goredis.NewPool(redisClient)
	rs = redsync.New(pool)
}

func main() {
	e := echo.New()
	e.Validator = &CustomValidator{validator: validator.New()}
	e.HTTPErrorHandler = customErrorHandler

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(rateLimiterMiddleware(rate.Limit(1), 5))

	e.POST("/login", login)
	e.POST("/users", createUser)

	r := e.Group("/api")
	r.Use(echojwt.JWT([]byte(os.Getenv("JWT_SECRET"))))
	r.GET("/users", getUsers)
	r.GET("/users/:id", getUser)
	r.PUT("/users/:id", updateUser)
	r.DELETE("/users/:id", deleteUser)

	logger.Info().Msg("Server started")
	e.Logger.Fatal(e.Start(":8080"))
}

func rateLimiterMiddleware(limit rate.Limit, burst int) echo.MiddlewareFunc {
	limiter := rate.NewLimiter(limit, burst)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !limiter.Allow() {
				return echo.NewHTTPError(http.StatusTooManyRequests, "rate limit exceeded")
			}
			return next(c)
		}
	}
}

func customErrorHandler(err error, c echo.Context) {
	var (
		code    = http.StatusInternalServerError
		message interface{}
	)

	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		message = he.Message
	} else {
		message = err.Error()
	}

	if !c.Response().Committed {
		if c.Request().Method == http.MethodHead {
			err = c.NoContent(code)
		} else {
			err = c.JSON(code, CustomError{Code: code, Message: fmt.Sprintf("%v", message)})
		}
		if err != nil {
			logger.Error().Err(err).Msg("Error in error handler")
		}
	}

	logger.Error().Err(err).Int("status", code).Msg("Request error")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func login(c echo.Context) error {
	var loginReq LoginRequest
	if err := c.Bind(&loginReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if err := c.Validate(loginReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	var user User
	if err := db.Where("email = ?", loginReq.Email).First(&user).Error; err != nil {
		logger.Warn().Err(err).Str("email", loginReq.Email).Msg("User not found")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	if !CheckPasswordHash(loginReq.Password, user.Password) {
		logger.Warn().Str("email", loginReq.Email).Msg("Invalid password")
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = user.ID

	// Token expires in 72 hours
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	t, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		logger.Error().Err(err).Msg("Failed to sign token")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to sign token")
	}

	logger.Info().Str("email", loginReq.Email).Msg("User logged in")
	return c.JSON(http.StatusOK, map[string]string{
		"access_token": t,
	})
}

func getUsers(c echo.Context) error {
	ctx := context.Background()
	cacheKey := "users"

	cachedUsers, err := redisClient.Get(ctx, cacheKey).Result()
	if err == nil {
		var users []User
		err = json.Unmarshal([]byte(cachedUsers), &users)
		if err == nil {
			logger.Info().Msg("Users fetched from cache")
			return c.JSON(http.StatusOK, users)
		}
	}

	result, err, _ := requestGroup.Do(cacheKey, func() (interface{}, error) {
		var users []User
		if err := db.Find(&users).Error; err != nil {
			logger.Error().Err(err).Msg("Failed to fetch users")
			return nil, echo.NewHTTPError(http.StatusInternalServerError, "Failed to fetch users")
		}

		usersJSON, err := json.Marshal(users)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to marshal users")
			return users, nil // Return users even if caching fails
		}

		err = redisClient.Set(ctx, cacheKey, usersJSON, 10*time.Minute).Err()
		if err != nil {
			logger.Warn().Err(err).Str("key", cacheKey).Msg("Failed to cache users")
		}

		logger.Info().Msg("Users fetched from database")
		return users, nil
	})

	if err != nil {
		return err
	}

	users := result.([]User)
	return c.JSON(http.StatusOK, users)
}

func getUser(c echo.Context) error {
	id := c.Param("id")
	ctx := context.Background()
	cacheKey := fmt.Sprintf("user_%s", id)

	cachedUser, err := redisClient.Get(ctx, cacheKey).Result()
	if err == nil {
		var user User
		err = json.Unmarshal([]byte(cachedUser), &user)
		if err == nil {
			logger.Info().Str("id", id).Msg("User fetched from cache")
			return c.JSON(http.StatusOK, user)
		}
	}

	result, err, _ := requestGroup.Do(cacheKey, func() (interface{}, error) {
		var user User
		if err := db.First(&user, id).Error; err != nil {
			logger.Warn().Err(err).Str("id", id).Msg("User not found")
			return nil, echo.NewHTTPError(http.StatusNotFound, "User not found")
		}

		userJSON, err := json.Marshal(user)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to marshal user")
			return user, nil // Return user even if caching fails
		}

		err = redisClient.Set(ctx, cacheKey, userJSON, 10*time.Minute).Err()
		if err != nil {
			logger.Warn().Err(err).Str("key", cacheKey).Msg("Failed to cache user")
		}

		logger.Info().Str("id", id).Msg("User fetched from database")
		return user, nil
	})

	if err != nil {
		return err
	}

	user := result.(User)
	return c.JSON(http.StatusOK, user)
}

func createUser(c echo.Context) error {
	user := new(User)
	if err := c.Bind(user); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if err := c.Validate(user); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	mutex := rs.NewMutex("create_user")
	if err := mutex.Lock(); err != nil {
		logger.Error().Err(err).Msg("Failed to acquire lock")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to acquire lock")
	}
	defer mutex.Unlock()

	if err := db.Create(user).Error; err != nil {
		logger.Error().Err(err).Msg("Failed to create user")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create user")
	}

	ctx := context.Background()
	cacheKey := fmt.Sprintf("user_%s", strconv.FormatUint(uint64(user.ID), 10))
	userJSON, err := json.Marshal(user)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to marshal user")
	} else {
		if err := redisClient.Set(ctx, cacheKey, userJSON, 10*time.Minute).Err(); err != nil {
			logger.Warn().Err(err).Str("key", cacheKey).Msg("Failed to cache user")

		}
	}

	logger.Info().Str("id", fmt.Sprint(user.ID)).Msg("User created")
	return c.JSON(http.StatusCreated, user)
}

func updateUser(c echo.Context) error {
	id := c.Param("id")
	var updateReq UpdateUserRequest
	if err := c.Bind(&updateReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if err := c.Validate(updateReq); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	mutex := rs.NewMutex("update_user_" + id)
	if err := mutex.Lock(); err != nil {
		logger.Error().Err(err).Str("id", id).Msg("Failed to acquire lock")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to acquire lock")
	}
	defer mutex.Unlock()

	var existingUser User
	if err := db.First(&existingUser, id).Error; err != nil {
		logger.Warn().Err(err).Str("id", id).Msg("User not found")
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	existingUser.Name = updateReq.Name
	existingUser.Email = updateReq.Email

	if err := db.Save(&existingUser).Error; err != nil {
		logger.Error().Err(err).Str("id", id).Msg("Failed to update user")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update user")
	}

	ctx := context.Background()
	cacheKey := fmt.Sprintf("user_%s", id)
	userJSON, err := json.Marshal(existingUser)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to marshal user")
	} else {
		if err := redisClient.Set(ctx, cacheKey, userJSON, 10*time.Minute).Err(); err != nil {
			logger.Warn().Err(err).Str("key", cacheKey).Msg("Failed to cache user")
		}
	}

	logger.Info().Str("id", id).Msg("User updated")
	return c.JSON(http.StatusOK, existingUser)
}

func deleteUser(c echo.Context) error {
	id := c.Param("id")

	mutex := rs.NewMutex("delete_user_" + id)
	if err := mutex.Lock(); err != nil {
		logger.Error().Err(err).Str("id", id).Msg("Failed to acquire lock")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to acquire lock")
	}
	defer mutex.Unlock()

	var user User
	if err := db.First(&user, id).Error; err != nil {
		logger.Warn().Err(err).Str("id", id).Msg("User not found")
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	if err := db.Delete(&user).Error; err != nil {
		logger.Error().Err(err).Str("id", id).Msg("Failed to delete user")
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user")
	}

	ctx := context.Background()
	cacheKey := fmt.Sprintf("user_%s", id)
	if err := redisClient.Del(ctx, cacheKey).Err(); err != nil {
		logger.Warn().Err(err).Str("key", cacheKey).Msg("Failed to delete cache")
	}

	logger.Info().Str("id", id).Msg("User deleted")
	return c.NoContent(http.StatusNoContent)
}

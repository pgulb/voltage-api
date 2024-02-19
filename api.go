package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// struct used to map user input when creating new user
type Register struct {
	Username string `form:"username" validate:"required,ascii,min=3,max=70"`
	Password string `form:"password" validate:"required,ascii,min=3,max=70"`
}

func loadMongoString() string {
	// loading MongoDB connection string from MONGO_CONN
	// first is checked enviironment var, then .env
	if mng := os.Getenv("MONGO_CONN"); mng != "" {
		return mng
	}

	err := godotenv.Load()
	if err != nil {
		log.Fatal("error loading .env file")
	}

	return os.Getenv("MONGO_CONN")
}

func mongoConnect() (*mongo.Client, error) {
	// create and return MongoDB connection client
	// client will be used in other functions
	connStr := loadMongoString()
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(connStr).SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		return nil, err
	}
	if err := client.Database(
		"admin").RunCommand(
		context.TODO(), bson.D{{Key: "ping", Value: 1}}).Err(); err != nil {
		return nil, err
	}
	return client, nil
}

func getUser(conn *mongo.Client, userid string) (string, string, error) {
	// find user in MongoDB
	// returns username, passhash and possible error
	// error should occur if none was found
	coll := conn.Database("gaem").Collection("users")
	user := make(map[string]interface{})
	proj := bson.D{
		{Key: "pass", Value: 1},
	}
	opts := options.FindOne().SetProjection(proj)
	filter := bson.D{{Key: "_id", Value: userid}}
	err := coll.FindOne(context.TODO(), filter, opts).Decode(&user)
	if err != nil {
		return "", "", err
	}
	return user["_id"].(string), user["pass"].(string), nil
}

func isEventInProgress(conn *mongo.Client, userid string) (bool, error) {
	// check if user has event_in_progress set to true
	coll := conn.Database("gaem").Collection("users")
	user := make(map[string]interface{})
	filter := bson.D{{Key: "_id", Value: userid}}
	proj := bson.D{
		{Key: "event_in_progress", Value: 1},
		{Key: "_id", Value: 0},
	}
	opts := options.FindOne().SetProjection(proj)
	err := coll.FindOne(context.TODO(), filter, opts).Decode(&user)
	if err != nil {
		return true, err
	}
	return user["event_in_progress"].(bool), nil
}

func mongoBasicAuth(conn *mongo.Client) gin.HandlerFunc {
	// basic auth middleware based on default gin auth
	// every login is checked in mongo
	// passwords in mongo are bcrypted
	realm := "Authorization Required"
	realm = "Basic realm=" + strconv.Quote(realm)
	return func(c *gin.Context) {
		if len(c.Request.Header["Authorization"]) == 0 {
			{
				c.Header("WWW-Authenticate", realm)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
		}
		b64 := c.Request.Header["Authorization"][0]
		b64 = strings.Split(b64, " ")[1]
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			log.Println(err)
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		splitted := strings.Split(string(decoded), ":")
		user := splitted[0]
		pass := splitted[1]

		userMongo, hashMongo, err := getUser(conn, user)
		if err != nil || user != userMongo {
			log.Println(err.Error())
			c.Header("WWW-Authenticate", realm)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashMongo), []byte(pass))
		if err != nil {
			c.Header("WWW-Authenticate", realm)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set(gin.AuthUserKey, user)
	}
}

func registerUser(user string, pass string, client *mongo.Client) error {
	// create user and insert into MongoDB
	// password is hashed with bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), 12)
	if err != nil {
		return err
	}
	userMongo, _, err := getUser(client, user)
	if userMongo != "" {
		return errors.New("user already exists")
	}
	if err == nil {
		return err
	}
	coll := client.Database("gaem").Collection("users")
	// username is _id in MongoDB to force uniqueness
	_, err = coll.InsertOne(context.TODO(), bson.D{
		{Key: "_id", Value: user},
		{Key: "pass", Value: string(hash)},
		{Key: "event_in_progress", Value: false},
	})
	if err != nil {
		return err
	}
	return nil
}

func pingMongo(client *mongo.Client) error {
	// test MongoDB connection
	// for readiness check
	if err := client.Database(
		"admin").RunCommand(
		context.TODO(), bson.D{{Key: "ping", Value: 1}}).Err(); err != nil {
		return err
	}
	return nil
}

func main() {
	// init validator
	validate := validator.New(validator.WithRequiredStructEnabled())

	mng, err := mongoConnect()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err = mng.Disconnect(context.TODO()); err != nil {
			log.Fatal(err)
		}
	}()
	log.Println("mongoDB connected successfully")

	// liveness and readiness endpoints
	r := gin.Default()
	r.GET("/live", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "OK",
		})
	})
	r.GET("/ready", func(c *gin.Context) {
		if ping := pingMongo(mng); ping != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "mongodb connection failed",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message": "OK",
		})
	})

	r.POST("/register", func(c *gin.Context) {
		// /register uses validator to check username and password rules
		var reg Register
		err := c.Bind(&reg)
		if reg.Username == "" || reg.Password == "" {
			c.JSON(http.StatusBadRequest,
				gin.H{"message": "provide necessary username and password"})
			return
		}
		if err != nil {
			c.JSON(http.StatusBadRequest,
				gin.H{"message": err.Error()})
			return
		}
		// validate username and password
		// 3-70 chars, ASCII only
		err = validate.Struct(reg)
		if err != nil {
			c.JSON(http.StatusBadRequest,
				gin.H{"message": err.Error()})
			return
		}
		err = registerUser(reg.Username, reg.Password, mng)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusConflict,
				gin.H{"message": err.Error()})
			return
		}
		c.JSON(http.StatusCreated,
			gin.H{"message": fmt.Sprintf("Created user %s", reg.Username)})
	})

	authorized := r.Group("/user", mongoBasicAuth(mng))
	authorized.GET("/login", func(c *gin.Context) {
		user := c.MustGet(gin.AuthUserKey).(string)
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Hello, %s", user)})
	})
	authorized.GET("/is_in_progress", func(c *gin.Context) {
		user := c.MustGet(gin.AuthUserKey).(string)
		isInProgress, err := isEventInProgress(mng, user)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest,
				gin.H{"message": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"event_in_progress": isInProgress})
	})
	authorized.POST("/event", func(c *gin.Context) {
		user := c.MustGet(gin.AuthUserKey).(string)
		isInProgress, err := isEventInProgress(mng, user)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest,
				gin.H{"message": err.Error()})
			return
		}
		if isInProgress {
			c.JSON(http.StatusLocked,
				gin.H{"message": "event is already in progress"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"message": "placeholder for success"})
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}

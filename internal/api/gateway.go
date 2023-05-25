package api

import (
	"ApiGateway/internal/config"
	"ApiGateway/internal/core/errorsCore"
	"ApiGateway/internal/models"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	protocol            = "http"
	baseURL             = "/api/v1/"
	requestID           = "X-request-ID"
	RedirectURLHeader   = "RedirectURL"
	infoEnd             = "endpoint-info/"
	defaultServicesCnt  = 5 // How many microservice's we have when starting ApiGateway
	authorizationHeader = "authorization"
	POST                = "POST"
	GET                 = "GET"
	PUT                 = "PUT"
	DELETE              = "DELETE"
	userID              = "UserID"
)

type GateWay struct {
	Logger          *zap.Logger
	conf            *models.Config
	router          *mux.Router
	routerProtected *mux.Router
}

func NewGateWay(cfg *models.Config) *GateWay {
	gw := &GateWay{conf: cfg, router: mux.NewRouter()}
	gw.conf.Services = config.ReadServicesList().ServiceList
	gw.Logger = NewLogger()
	gw.registerHandlers()

	return gw
}

func (gw *GateWay) Start() error {
	gw.registerNewHandlers()
	gw.Logger.Info("Start to listen to", zap.String("port", gw.conf.Listen.Port))
	err := http.ListenAndServe(":"+gw.conf.Listen.Port, gw.router) //nolint:gosec, gofmt, nolintlint
	if err != nil {
		return errorsCore.WrapError("can't Start() Gateway", err)
	}

	return nil
}

func (gw *GateWay) registerHandlers() {
	gw.router.Use(gw.setRequestID)
	gw.router.Use(gw.setCorsAccess)
	gw.router.Use(gw.logRequest)
	gw.routerProtected = gw.router.NewRoute().Subrouter()
	gw.routerProtected.Use(gw.setRequestID, gw.verifyToken, gw.setCorsAccess, gw.addUserIDHeader)
	gw.router.Path(baseURL+"hello").Handler(gw.handleHello()).Methods(POST, GET)
}

func (gw *GateWay) registerNewHandlers() {
	list := make(map[string]func(string, string) http.HandlerFunc)
	list["user"] = gw.handleRedirectUserService
	list["pet"] = gw.handleRedirectService
	list["image"] = gw.handleRedirectImageService
	list["advert"] = gw.handleRedirectService

	for _, srv := range gw.conf.Services {
		fn, ok := list[srv.Name]
		if ok {
			regService(srv, gw, fn)
		}
	}
}

func (gw *GateWay) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(requestID) == "" {
			id := uuid.New().String()
			r.Header.Set(requestID, id)
		}
		next.ServeHTTP(w, r)
	})
}

func (gw *GateWay) addUserIDHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Get("ExpiredIn")) > 0 {
			next.ServeHTTP(w, r)
			r.Header.Del(userID)
		}
		providedToken := strings.Split(r.Header.Get(authorizationHeader), " ")[1]
		payload, err := parseToken(providedToken)
		if err != nil {
			gw.warning(w, http.StatusUnauthorized,
				errorsCore.ErrInvalidToken, err.Error())

			return
		}
		id := payload.ProfileID
		r.Header.Set(userID, id.String())
		next.ServeHTTP(w, r)
		r.Header.Del(userID)
	})
}

func (gw *GateWay) setCorsAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, PATCH, DELETE") //nolint:goconst
		w.Header().Set("Access-Control-Request-Method", "POST, GET, OPTIONS, PUT, PATCH, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type") //nolint:goconst
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Headers",
				"Content-Type, Accept, Authorization, Access-Control-Allow-Origin, Access-Control-Allow-Headers, FingerPrint, Origin, X-Requested-With") //nolint:lll
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, PATCH, DELETE")
			r.Header.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, PATCH, DELETE")
		}
		next.ServeHTTP(w, r)
	})
}

// Building URL address for handlers.
func buildURLHandler(ip string, port string) (*url.URL, error) {
	redirectURL, err := url.Parse(protocol + "://" + ip + ":" + port)
	if err != nil {
		return nil, errorsCore.WrapError(errorsCore.ErrParseHandleURL.Error(), err)
	}

	return redirectURL, nil
}

func (gw *GateWay) handleRedirectUserService(ip string, port string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURL, err := buildURLHandler(ip, port)
		if err != nil {
			gw.Logger.Error("error handleRedirectUserService url parse", zap.Error(err))
		}
		proxy := httputil.NewSingleHostReverseProxy(redirectURL)
		r.Header.Set(RedirectURLHeader, redirectURL.String())
		proxy.ServeHTTP(w, r)
	}
}

func (gw *GateWay) handleRedirectService(ip string, port string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURL, err := buildURLHandler(ip, port)
		if err != nil {
			gw.Logger.Error("error handleRedirectService url parse", zap.Error(err))
		}
		proxy := httputil.NewSingleHostReverseProxy(redirectURL)
		r.Header.Set(RedirectURLHeader, redirectURL.String())
		proxy.ServeHTTP(w, r)
	}
}

func (gw *GateWay) handleRedirectImageService(ip string, port string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURL, err := buildURLHandler(ip, port)
		if err != nil {
			gw.Logger.Error("error handleRedirectService url parse", zap.Error(err))
		}

		client := new(http.Client)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return errors.New("redirect")
		}

		/*fileDir, _ := os.Getwd()
		fileName := "some"
		filePath := path.Join(fileDir, fileName)

		file, _ := os.Open(filePath)
		*/

		err = r.ParseMultipartForm(32 << 20)
		if err != nil {
			gw.Logger.Sugar().Fatalf("error parse multipart form, err: %v", err)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			gw.Logger.Sugar().Fatalf("request isn't multipart form data, err: %v", err)
			return
		}
		defer func(file multipart.File) {
			err := file.Close()
			if err != nil {
				gw.Logger.Sugar().Fatalf("failed to close file, err: %v", err)
			}
		}(file)

		temp := &bytes.Buffer{}
		writer := multipart.NewWriter(temp)
		part, _ := writer.CreateFormFile("file", filepath.Base("file"))
		_, err = io.Copy(part, file)
		if err != nil {
			gw.Logger.Sugar().Fatalf("failed to copy data from file, err: %v", err)
			return
		}
		err = writer.Close()
		if err != nil {
			gw.Logger.Sugar().Fatalf("failed to close writer, err: %v", err)
			return
		}

		gw.Logger.Sugar().Infof("info about user before imageService: %v", temp)

		req, err := http.NewRequest("POST", redirectURL.String()+r.RequestURI, temp)
		if err != nil {
			gw.Logger.Fatal("req err")
		}
		req.Header.Add("Content-Type", writer.FormDataContentType())

		response, err := client.Do(req)
		if err != nil {
			gw.Logger.Fatal("Redirect err")
		}

		body, err := io.ReadAll(response.Body)

		type UserData struct {
			Origin string `json:"origin"`
		}

		type PetData struct {
			Origin    string `json:"origin"`
			Thumbnail string `json:"thumbnail"`
		}

		type ResUser struct {
			StatusCode int      `json:"statusCode"`
			Message    string   `json:"message"`
			UserData   UserData `json:"data"`
		}

		type ResPet struct {
			StatusCode int     `json:"statusCode"`
			Message    string  `json:"message"`
			PetData    PetData `json:"data"`
			PetCardID  int     `json:"petCardID"`
		}

		petID := r.Form.Get("petID")
		user := ResUser{}
		pet := ResPet{}
		if r.RequestURI == "/api/v1/fileUser" {
			err := json.Unmarshal(body, &user)
			if err != nil {
				gw.Logger.Sugar().Errorf("failed to unmarshal json %v", err)
				return
			}
			var buf bytes.Buffer
			err = json.NewEncoder(&buf).Encode(user)
			if err != nil {
				gw.Logger.Sugar().Errorf("failed to encode json %v", err)
				return
			}
			gw.Logger.Sugar().Infof("info about user after imageService: %s", user.UserData.Origin)
			//redirectURL.Host = redirectURL.Host[:len(redirectURL.Host)-4] + "6001"
			redString := "http://" + os.Getenv("USERSERVICE_IP") + ":" + os.Getenv("USERSERVICE_PORT") + "/api/v1/user/image/set"
			userReq, err := http.NewRequest("POST", redString, &buf)
			if err != nil {
				gw.Logger.Fatal("req err")
			}
			userReq.Header.Add("Content-Type", "application/json")
			providedToken := strings.Split(r.Header.Get(authorizationHeader), " ")[1]
			payload, err := parseToken(providedToken)
			if err != nil {
				gw.warning(w, http.StatusUnauthorized,
					errorsCore.ErrInvalidToken, err.Error())

				return
			}
			id := payload.ProfileID
			userReq.Header.Set(userID, id.String())

			tempRes, err := client.Do(userReq)
			if err != nil {
				gw.Logger.Fatal("Client.Do error")
			}
			println(tempRes)
		}
		if r.RequestURI == "/api/v1/filePet" {
			err := json.Unmarshal(body, &pet)
			if err != nil {
				gw.Logger.Sugar().Errorf("failed to unmarshal json %v", err)
				return
			}
			pet.PetCardID, err = strconv.Atoi(petID)
			if err != nil {
				gw.Logger.Sugar().Errorf("failed to convert string to int %v", err)
				return
			}

			var buf bytes.Buffer
			err = json.NewEncoder(&buf).Encode(pet)
			if err != nil {
				gw.Logger.Sugar().Errorf("failed to encode json %v", err)
				return
			}
			//redirectURL.Host = redirectURL.Host[:len(redirectURL.Host)-4] + "6003"
			redString := "http://" + os.Getenv("PETSERVICE_IP") + ":" + os.Getenv("PETSERVICE_PORT") + "/api/v1/petCards/image/set"
			userReq, err := http.NewRequest("POST", redString, &buf)
			if err != nil {
				gw.Logger.Fatal("req err")
			}
			userReq.Header.Add("Content-Type", "application/json")
			providedToken := strings.Split(r.Header.Get(authorizationHeader), " ")[1]
			payload, err := parseToken(providedToken)
			if err != nil {
				gw.warning(w, http.StatusUnauthorized,
					errorsCore.ErrInvalidToken, err.Error())

				return
			}
			id := payload.ProfileID
			userReq.Header.Set(userID, id.String())

			tempRes, err := client.Do(userReq)
			if err != nil {
				gw.Logger.Fatal("Client.Do error")
			}
			println(tempRes)
		}

	}
}

func (gw *GateWay) handleDefault(ip string, port string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURL, err := buildURLHandler(ip, port)
		if err != nil {
			gw.Logger.Error("error handleDefault url parse", zap.Error(err))
		}
		proxy := httputil.NewSingleHostReverseProxy(redirectURL)
		r.Header.Set(RedirectURLHeader, redirectURL.String())

		w.Header().Del("Access-Control-Allow-Origin")
		w.Header().Del("Access-Control-Allow-Methods")
		w.Header().Del("Access-Control-Request-Method")
		w.Header().Del("Access-Control-Allow-Headers")
		proxy.ServeHTTP(w, r)
	}
}

func (gw *GateWay) handleHello() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if _, err := w.Write([]byte("HELLO FROM APIGateway, GET method")); err != nil {
				gw.Logger.Warn(err.Error())
			}
			name := r.URL.Query().Get("service")
			ip := strings.Split(r.RemoteAddr, ":")[0]
			port := r.URL.Query().Get("port")

			for k, v := range gw.conf.Services {
				if v.Name == name {
					gw.conf.Services[k].IP = ip
					gw.conf.Services[k].Port = port
				}
			}

			return
		}

		instance := models.Service{}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			gw.Logger.Warn(errorsCore.ErrReadResponseBody.Error() + " " + err.Error())

			return
		}
		if err := json.Unmarshal(body, &instance); err != nil {
			gw.Logger.Warn(err.Error())
		}
		if _, err := w.Write([]byte("HELLO FROM APIGateway")); err != nil {
			gw.Logger.Warn(err.Error())
		}
		if err := CheckService(gw, instance); err != nil {
			gw.Logger.Warn(err.Error())
		}

		gw.registerNewHandlers()
	}
}

const servicesCount = 5

func (gw *GateWay) getServices() ([]string, error) {
	// GO to endpoint-info/ receive json, update our
	serversList := make([]string, 0, servicesCount)
	for _, serv := range gw.conf.Services {
		serviceURL, err := url.Parse(
			protocol + "://" + serv.IP + ":" + serv.Port + baseURL + infoEnd)
		if err != nil {
			return nil, errorsCore.WrapError("getServices() can't parse service url"+serviceURL.String(), err)
		}
		serversList = append(serversList, serviceURL.String())
	}

	return serversList, nil
}

func getServicesInfo(serversList []string) (map[string]models.Service, error) {
	parsedServices := make(map[string]models.Service)

	for _, service := range serversList {
		var parsed *models.Service
		resp, err := http.Get(service) //nolint: gosec, noctx
		if resp == nil {
			// FIXME:Super dirty. Need to handle error, when http.Get() can't reach service
			continue
		}
		if err != nil {
			return nil, errorsCore.WrapError("error service info http.Get(service)", err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errorsCore.WrapError(errorsCore.ErrReadResponseBody.Error(), err)
		}
		if err := resp.Body.Close(); err != nil {
			return nil, errorsCore.WrapError(errorsCore.ErrCloseResponseBody.Error(), err)
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, errorsCore.WrapError("can't Unmarshal response body", err)
		}
		newParsed := *parsed
		parsedServices[newParsed.Name] = newParsed
	}

	return parsedServices, nil
}

func (gw *GateWay) UpdateServicesInfo(list []string) error { //nolint: cyclop
	// TODO:Set version of endpoints info, and check it here
	// if version same, don't update list

	var (
		servicesList []string
		err          error
	)
	if len(list) > 0 {
		// if we passed updated list use it (len>0), if not parse config file
		servicesList = list
	} else {
		servicesList, err = gw.getServices()
		if err != nil {
			return errorsCore.WrapError("error while UpdateServicesInfo()", err)
		}
	}
	servicesInfo, err := getServicesInfo(servicesList)
	if err != nil {
		return errorsCore.WrapError("can't getServicesInfo", err)
	}
	servicesFile, err := os.Create("services.json")
	if err != nil {
		return errorsCore.WrapError(errorsCore.ErrCantWriteFile.Error(), err)
	}
	defer func() {
		if err := servicesFile.Close(); err != nil {
			gw.Logger.Error(err.Error())
		}
	}()
	// Json Header writing
	if _, err := servicesFile.Write([]byte("{\"serviceList\":[")); err != nil {
		return errorsCore.WrapError(errorsCore.ErrCantWriteFile.Error(), err)
	}
	objCnt := len(servicesInfo) - 1
	var i int
	for _, serv := range servicesInfo {
		gw.conf.Services = append(gw.conf.Services, serv)
		var buf bytes.Buffer
		payload, err := json.MarshalIndent(serv, "", "\t")
		if err != nil {
			return errorsCore.WrapError("can't marshal service form serviceInfo", err)
		}
		if _, err := buf.Write(payload); err != nil {
			return errorsCore.WrapError(errorsCore.ErrCantWriteFile.Error(), err)
		}
		if i < objCnt {
			// Adding comma between objects ins array
			buf.Write([]byte(","))
		}
		_, err = servicesFile.Write(buf.Bytes())
		if err != nil {
			return errorsCore.WrapError(errorsCore.ErrCantWriteFile.Error(), err)
		}
		i++
	}
	if _, err := servicesFile.Write([]byte("]}")); err != nil {
		return errorsCore.WrapError(errorsCore.ErrCantWriteFile.Error(), err)
	}

	return nil
}

func regService(srv models.Service, gw *GateWay, fn func(string, string) http.HandlerFunc) {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"*"},
	})
	var domain string
	domain = srv.IP
	for _, endpoint := range srv.Endpoints {
		if endpoint.Protected {
			gw.routerProtected.Path(baseURL +
				endpoint.URL).Handler(c.Handler(fn(domain, srv.Port))).Methods(endpoint.Methods...)
		} else {
			gw.router.Path(baseURL +
				endpoint.URL).Handler(c.Handler(fn(domain, srv.Port))).Methods(endpoint.Methods...)
		}
	}
}

func CheckService(gw *GateWay, serv models.Service) error {
	var domain string
	servicesNames := make([]string, 0, defaultServicesCnt)
	domain = serv.IP

	servicesList, err := gw.getServices()
	if err != nil {
		return errorsCore.WrapError("error while CheckService()", err)
	}

	// Gether current services names
	for _, s := range gw.conf.Services {
		servicesNames = append(servicesNames, s.Name)
	}

	// Iterate through services names, if there is no new service add it,
	// if service present in list just run Update
	var cnt int
	for _, name := range servicesNames {
		if name == serv.Name {
			cnt++
		}
	}

	if cnt > 0 {
		// No new services added
		if err := gw.UpdateServicesInfo(servicesList); err != nil {
			return err
		}

		return nil
	}

	url := fmt.Sprintf(protocol + "://" + domain + ":" + serv.Port + baseURL + infoEnd)
	servicesList = append(servicesList, url)
	if err := gw.UpdateServicesInfo(servicesList); err != nil {
		return errorsCore.WrapError(errorsCore.ErrCantWriteFile.Error(), err)
	}

	return nil
}

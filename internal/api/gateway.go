package api

import (
	"ApiGateway/internal/config"
	"ApiGateway/internal/core/errorsCore"
	"ApiGateway/internal/models"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
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

type gateWay struct {
	Logger          *zap.Logger
	conf            *models.Config
	router          *mux.Router
	routerProtected *mux.Router
}

func NewGateWay(cfg *models.Config) *gateWay {
	gw := &gateWay{conf: cfg, router: mux.NewRouter()}
	gw.Logger = NewLogger(cfg.IsLocal)
	gw.registerHandlers()

	return gw
}

func (gw *gateWay) Start() error {
	if err := gw.UpdateServicesInfo([]string{}); err != nil {
		gw.Logger.Error("can't UpdateServicesInfo " + err.Error())
	}
	gw.Logger.Info("Start to listen to", zap.String("port", gw.conf.Listen.Port))
	err := http.ListenAndServe(":"+gw.conf.Listen.Port, gw.router) //nolint:gosec, gofmt, nolintlint
	if err != nil {
		return errorsCore.WrapError("can't Start() Gateway", err)
	}

	return nil
}

func (gw *gateWay) registerHandlers() {
	gw.router.Use(gw.setRequestID)
	gw.router.Use(gw.setCorsAccess)
	gw.router.Use(gw.logRequest)
	gw.routerProtected = gw.router.NewRoute().Subrouter()
	gw.routerProtected.Use(gw.setRequestID, gw.verifyToken, gw.setCorsAccess, gw.addUserIDHeader)
	gw.router.Path(baseURL+"hello/").Handler(gw.handleHello()).Methods(POST, GET)
	gw.registerNewHandlers()
}

func (gw *gateWay) registerNewHandlers() {
	list := make(map[string]func(string, string) http.HandlerFunc)
	list["user"] = gw.handleRedirectUserService
	list["pet"] = gw.handleDefault

	conf := ReadConfig(gw)
	for _, srv := range conf.Services {
		fn, ok := list[srv.Name]
		if ok {
			// srv.Label = "pl-userservice-dev"
			regService(srv, gw, fn)
		}
	}
}

func ReadConfig(gw *gateWay) *models.Config {
	instance := &models.Config{}
	var configType string
	if gw.IsLocalRunning() {
		configType = "local"
	} else {
		configType = "config"
	}

	err := cleanenv.ReadConfig(fmt.Sprintf("./conf/%s.json", configType), instance)
	if err != nil {
		log.Fatalf("can't read config. %s", err.Error())
	}
	srvList := config.ReadServicesList()

	instance.Services = append(instance.Services, srvList.ServiceList...)

	return instance
}

func (gw *gateWay) IsLocalRunning() bool {
	return gw.conf.IsLocal
}

func (gw *gateWay) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(requestID) == "" {
			id := uuid.New().String()
			r.Header.Set(requestID, id)
		}
		next.ServeHTTP(w, r)
	})
}

func (gw *gateWay) addUserIDHeader(next http.Handler) http.Handler {
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

func (gw *gateWay) setCorsAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, PATCH, DELETE") //nolint:goconst
		w.Header().Set("Access-Control-Request-Method", "POST, GET, OPTIONS, PUT, PATCH, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type") //nolint:goconst
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Headers",
				"Content-Type, Accept, Authorization, access-control-allow-origin, access-control-allow-headers, FingerPrint, Origin, X-Requested-With") //nolint:lll
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

func (gw *gateWay) handleRedirectUserService(ip string, port string) http.HandlerFunc {
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

func (gw *gateWay) handleDefault(ip string, port string) http.HandlerFunc {
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

func (gw *gateWay) handleHello() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if _, err := w.Write([]byte("HELLO FROM APIGateway, GET method")); err != nil {
				gw.Logger.Warn(err.Error())
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
	}
}

const servicesCount = 5

func getServices(gw *gateWay) ([]string, error) {
	// GO to endpoint-info/ receive json, update our
	services := config.ReadServicesList()
	var domain string
	isLocal := gw.IsLocalRunning()
	serversList := make([]string, 0, servicesCount)
	for _, serv := range services.ServiceList {
		if isLocal {
			domain = serv.IP
		} else {
			domain = serv.Label
		}
		serviceURL, err := url.Parse(
			protocol + "://" + domain + ":" + serv.Port + baseURL + infoEnd)
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

func (gw *gateWay) UpdateServicesInfo(list []string) error { //nolint: cyclop
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
		servicesList, err = getServices(gw)
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
	gw.registerNewHandlers()

	return nil
}

func regService(srv models.Service, gw *gateWay, fn func(string, string) http.HandlerFunc) {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"*"},
	})
	var domain string
	isLocal := gw.IsLocalRunning()

	if isLocal {
		domain = srv.IP
	} else {
		domain = srv.Label
	}
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

func CheckService(gw *gateWay, serv models.Service) error {
	var domain string
	servicesNames := make([]string, 0, defaultServicesCnt)

	isLocal := gw.IsLocalRunning()
	if isLocal {
		domain = serv.IP
	} else {
		domain = serv.Label
	}

	servicesList, err := getServices(gw)
	if err != nil {
		return errorsCore.WrapError("error while CheckService()", err)
	}

	// Gether current services names
	services := config.ReadServicesList()
	for _, s := range services.ServiceList {
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

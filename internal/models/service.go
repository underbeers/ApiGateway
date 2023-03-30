package models

type Service struct {
	Name      string `json:"name"`
	Port      string `json:"port"`
	IP        string `json:"ip"`
	Endpoints []struct {
		URL       string   `json:"url"`
		Protected bool     `json:"protected"`
		Methods   []string `json:"methods"`
	} `json:"endpoints"`
}

type ServiceList struct {
	ServiceList []Service `json:"serviceList"`
}

func (s *Service) JSONConv(remoteAddr string) {
	s.IP = remoteAddr
}

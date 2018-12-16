package config

import (
	"io/ioutil"
	"gopkg.in/yaml.v2"
)

type Config map[string]*Module

type Module struct {
	// A list of OIDs.
	Walk       []string   `yaml:"walk,omitempty"`
	Get        []string   `yaml:"get,omitempty"`
	Metrics    []*Metric  `yaml:"metrics"`
}

type Metric struct {
	Name           string                     `yaml:"name"`
	Oid            string                     `yaml:"oid"`
	Type           string                     `yaml:"type"`
	Help           string                     `yaml:"help"`
	Indexes        []*Index                   `yaml:"indexes,omitempty"`
	Lookups        []*Lookup                  `yaml:"lookups,omitempty"`
}
type Label struct {
	Labelname string
	Labelvalues []string
}

type Index struct {
	Labelname string `yaml:"labelname"`
	Type      string `yaml:"type"`
	FixedSize int    `yaml:"fixed_size,omitempty"`
}
type Lookup struct {
	Labels    []string `yaml:"labels"`
	Labelname string   `yaml:"labelname"`
	Oid       string   `yaml:"oid"`
	Type      string   `yaml:"type"`
}

type Auth struct {
	Community     string `yaml:"community,omitempty"`
	SecurityLevel string `yaml:"security_level,omitempty"`
	Username      string `yaml:"username,omitempty"`
	Password      string `yaml:"password,omitempty"`
	AuthProtocol  string `yaml:"auth_protocol,omitempty"`
	PrivProtocol  string `yaml:"priv_protocol,omitempty"`
	PrivPassword  string `yaml:"priv_password,omitempty"`
	ContextName   string `yaml:"context_name,omitempty"`
}

type NMetric struct {
	Name string `yaml:"name"`
	Oid string `yaml:"oid"`
	Value string `yaml:"value"`
	Policy string `yaml:"policy,omitempty"`
	Indexes []*NMetric `yaml:"indexes,omitempty"`
}
type NMetricAndType struct{
	Type string `yaml:"type"`
	AllMetrics []*NMetric `yaml:"allmetrics"`
}
type NModule struct {
	NMetric []*NMetricAndType `yaml:"metrics"`
}
func LoadFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	err = yaml.UnmarshalStrict(content, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
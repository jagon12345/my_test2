package manager

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"

	"github.com/shipyard/shipyard"
)

func getTLSConfig(caCert, sslCert, sslKey []byte) (*tls.Config, error) {
	// TLS config
	var tlsConfig tls.Config
	tlsConfig.InsecureSkipVerify = true
	certPool := x509.NewCertPool()

	certPool.AppendCertsFromPEM(caCert)
	tlsConfig.RootCAs = certPool
	cert, err := tls.X509KeyPair(sslCert, sslKey)
	if err != nil {
		return &tlsConfig, err
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	return &tlsConfig, nil
}

func generateId(n int) string {
	hash := sha256.New()
	hash.Write([]byte(time.Now().String()))
	md := hash.Sum(nil)
	mdStr := hex.EncodeToString(md)
	return mdStr[:n]
}

func parseClusterNodes(driverStatus [][]string) ([]*shipyard.Node, error) {
	nodes := []*shipyard.Node{}
	var node *shipyard.Node
	nodeComplete := false
	name := ""
	addr := ""
	containers := ""
	reservedCPUs := ""
	reservedMemory := ""
	labels := []string{}
	for _, l := range driverStatus {
		if len(l) != 2 {
			continue
		}
		label := l[0]
		data := l[1]

		// cluster info label i.e. "Filters" or "Strategy"
		if strings.Index(label, "\u0008") > -1 {
			continue
		}

		if strings.Index(label, " └") == -1 {
			name = label
			addr = data
		}

		// node info like "Containers"
		switch label {
		case " └ Containers":
			containers = data
		case " └ Reserved CPUs":
			reservedCPUs = data
		case " └ Reserved Memory":
			reservedMemory = data
		case " └ Labels":
			lbls := strings.Split(data, ",")
			labels = lbls
			nodeComplete = true
		default:
			continue
		}

		// using shipyard encrypt addr.
		// we use id to get node info instead of name because name will duplicate.
		// 使用shipyard单词加密节点地址"192.168..."
		// 节点信息里的name域名很容易冲突，都是"localhost.localdomain"
		// 对于节点监控我们需要获取节点信息，直接使用地址"192..."不太好，加密一下先
		// 加密方法可以改变一下，暂时没怎么学

		// 使用base64对url加密，不用加id了...
		//id = Encrypt([]byte(addr), "shipyard")

		if nodeComplete {
			node = &shipyard.Node{
				Name:           name,
				Addr:           addr,
				Containers:     containers,
				ReservedCPUs:   reservedCPUs,
				ReservedMemory: reservedMemory,
				Labels:         labels,
			}
			nodes = append(nodes, node)

			// reset info
			name = ""
			addr = ""
			containers = ""
			reservedCPUs = ""
			reservedMemory = ""
			labels = []string{}
			nodeComplete = false
		}
	}

	return nodes, nil
}

package commands

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/passoz/pwn/internal/harness/panel"
	"github.com/passoz/pwn/internal/platform/logx"
)

// ServeOptions são os parâmetros aceitos por `pwn serve`.
type ServeOptions struct {
	Host  string
	Port  int
	Token string
}

// Serve sobe o painel de observabilidade em modo somente leitura.
func (r *Runner) Serve(args []string) int {
	options, err := parseServeOptions(args, r.ServeToken)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ %s\n", err.Error())
		fmt.Fprint(r.out(), "\nUso:\n")
		fmt.Fprint(r.out(), "  pwn serve [--host 127.0.0.1] [--port 7932] [--token <segredo>]\n")
		fmt.Fprint(r.out(), "  Host não local exige token, por --token ou PWN_SERVE_TOKEN.\n")
		return 2
	}

	if !logx.IsLoopback(options.Host) && options.Token == "" {
		fmt.Fprintf(r.errOut(), "✗ host %q não é local: informe --token ou PWN_SERVE_TOKEN\n", options.Host)
		return 1
	}

	address := net.JoinHostPort(options.Host, strconv.Itoa(options.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Fprintf(r.errOut(), "✗ escutar em %s: %v\n", address, err)
		return 1
	}

	server := &http.Server{
		Handler: panel.Handler(panel.Options{
			Root:    r.rootDir(),
			Token:   options.Token,
			Version: r.Version,
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Fprintf(r.out(), "=== [pwn serve] Painel de observabilidade ===\n")
	fmt.Fprintf(r.out(), "Raiz: %s\n", r.rootDir())
	fmt.Fprintf(r.out(), "Endereço: http://%s\n", listener.Addr().String())
	if options.Token != "" {
		fmt.Fprintln(r.out(), "Autenticação: token exigido (Authorization: Bearer <token> ou ?token=)")
	}
	if r.Log != nil {
		r.Log.Info("serve.start", "address", listener.Addr().String(), "root", r.rootDir())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		close(done)
	}()

	err = server.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(r.errOut(), "✗ servidor: %v\n", err)
		if r.Log != nil {
			r.Log.Error("serve.error", "error", err.Error())
		}
		return 1
	}
	<-done
	if r.Log != nil {
		r.Log.Info("serve.stop", "address", listener.Addr().String())
	}
	return 0
}

func parseServeOptions(args []string, defaultToken string) (ServeOptions, error) {
	options := ServeOptions{Host: "127.0.0.1", Port: 7932, Token: defaultToken}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		name, value, hasValue := strings.Cut(arg, "=")
		takeValue := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if index+1 >= len(args) {
				return "", fmt.Errorf("%s exige um valor", name)
			}
			index++
			return args[index], nil
		}
		switch name {
		case "--host":
			parsed, err := takeValue()
			if err != nil {
				return ServeOptions{}, err
			}
			if parsed == "" {
				return ServeOptions{}, fmt.Errorf("--host não pode ser vazio")
			}
			options.Host = parsed
		case "--port":
			parsed, err := takeValue()
			if err != nil {
				return ServeOptions{}, err
			}
			port, convErr := strconv.Atoi(parsed)
			if convErr != nil || port < 1 || port > 65535 {
				return ServeOptions{}, fmt.Errorf("porta inválida: %q", parsed)
			}
			options.Port = port
		case "--token":
			parsed, err := takeValue()
			if err != nil {
				return ServeOptions{}, err
			}
			if parsed == "" {
				return ServeOptions{}, fmt.Errorf("--token não pode ser vazio")
			}
			options.Token = parsed
		default:
			return ServeOptions{}, fmt.Errorf("argumento desconhecido: %s", arg)
		}
	}
	return options, nil
}

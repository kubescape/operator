package notificationhandler

import (
	"context"
	"fmt"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/operator/config"
	"github.com/panjf2000/ants/v2"

	"github.com/armosec/cluster-notifier-api-go/notificationserver"
	"github.com/gorilla/websocket"
)

type NotificationHandler struct {
	connector IWebsocketActions
	pool      *ants.PoolWithFunc
	config    config.IConfig
}

func NewNotificationHandler(pool *ants.PoolWithFunc, config config.IConfig) *NotificationHandler {
	urlStr := initNotificationServerURL(config)

	return &NotificationHandler{
		connector: NewWebsocketActions(urlStr),
		pool:      pool,
		config:    config,
	}
}

func (notification *NotificationHandler) WebsocketConnection(ctx context.Context) error {
	if notification.config.GatewayWebsocketURL() == "" {
		return nil
	}
	for {
		if err := notification.setupWebsocket(ctx); err != nil {
			time.Sleep(2 * time.Second)
		}
	}
}

// Websocket main function
func (notification *NotificationHandler) setupWebsocket(ctx context.Context) error {
	errs := make(chan error)
	_, err := notification.connector.DefaultDialer(nil)
	if err != nil {
		return err
	}
	defer notification.connector.Close()
	go func() {
		if err := notification.websocketPingMessage(ctx); err != nil {
			logger.L().Ctx(ctx).Error(err.Error(), helpers.Error(err))
			errs <- err
		}
	}()
	go func() {
		logger.L().Info("Waiting for websocket to receive notifications")
		if err := notification.websocketReceiveNotification(ctx); err != nil {
			logger.L().Ctx(ctx).Error(err.Error(), helpers.Error(err))
			errs <- err
		}
	}()

	return <-errs
}
func (notification *NotificationHandler) websocketReceiveNotification(ctx context.Context) error {
	for {
		messageType, messageBytes, err := notification.connector.ReadMessage()
		if err != nil {
			return fmt.Errorf("error receiving data from notificationServer. message: %s", err.Error())
		}

		switch messageType {
		case websocket.TextMessage, websocket.BinaryMessage:
			var notif *notificationserver.Notification
			switch messageBytes[0] {
			case '{', '[', '"':
				notif, err = decodeJsonNotification(messageBytes)
				if err != nil {
					notif, err = decodeBsonNotification(messageBytes)
					if err != nil {
						logger.L().Ctx(ctx).Error("failed to handle notification", helpers.String("messageBytes", string(messageBytes)), helpers.Error(err))
						continue
					}
				}
			default:
				notif, err = decodeBsonNotification(messageBytes)
				if err != nil {
					logger.L().Ctx(ctx).Error("failed to handle notification as BSON", helpers.String("messageBytes", string(messageBytes)), helpers.Error(err))
					continue
				}
			}

			err := notification.handleNotification(ctx, notification.config, notif)
			if err != nil {
				logger.L().Ctx(ctx).Error("failed to handle notification", helpers.String("messageBytes", string(messageBytes)), helpers.Error(err))
			}
		case websocket.CloseMessage:
			return fmt.Errorf("websocket closed by server, message: %s", string(messageBytes))
		default:
			logger.L().Info(fmt.Sprintf("Unrecognized message received. received: %d", messageType))
		}
	}
}

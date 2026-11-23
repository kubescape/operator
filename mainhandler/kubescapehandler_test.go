package mainhandler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	armoapi "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/k8s-interface/k8sinterface"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const kubescapeTestNamespace = "kubescape"

func kubescapeCronJobHandler(t *testing.T, enabled bool, client *fake.Clientset, cmd *armoapi.Command) *ActionHandler {
	t.Helper()
	cfg, err := config.NewOperatorConfig(
		config.CapabilitiesConfig{Components: config.Components{KubescapeScheduler: config.Component{Enabled: enabled}}},
		utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, config.Config{Namespace: kubescapeTestNamespace},
	)
	require.NoError(t, err)
	return &ActionHandler{
		config:     cfg,
		k8sAPI:     &k8sinterface.KubernetesApi{KubernetesClient: client},
		sessionObj: &utils.SessionObj{Command: cmd},
	}
}

func TestGetKubescapeJobParams(t *testing.T) {
	assert.Nil(t, getKubescapeJobParams(nil))
	assert.Nil(t, getKubescapeJobParams(&armoapi.Command{}))

	t.Run("from jobParams arg", func(t *testing.T) {
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"jobParams": armoapi.CronJobParams{JobName: "ks-job-1", CronTabSchedule: "0 1 * * *"},
			},
		}
		got := getKubescapeJobParams(cmd)
		require.NotNil(t, got)
		assert.Equal(t, "ks-job-1", got.JobName)
		assert.Equal(t, "0 1 * * *", got.CronTabSchedule)
	})

	t.Run("from kubescapeJobParams struct fallback", func(t *testing.T) {
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"kubescapeJobParams": armoapi.CronJobParams{JobName: "ks-job-2", CronTabSchedule: "0 2 * * *"},
			},
		}
		got := getKubescapeJobParams(cmd)
		require.NotNil(t, got)
		assert.Equal(t, "ks-job-2", got.JobName)
		assert.Equal(t, "0 2 * * *", got.CronTabSchedule)
	})

	t.Run("from kubescapeJobParams map fallback", func(t *testing.T) {
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"kubescapeJobParams": map[string]interface{}{
					"jobName":         "ks-job-3",
					"cronTabSchedule": "0 3 * * *",
				},
			},
		}
		got := getKubescapeJobParams(cmd)
		require.NotNil(t, got)
		assert.Equal(t, "ks-job-3", got.JobName)
		assert.Equal(t, "0 3 * * *", got.CronTabSchedule)
	})
}

func TestGetCronTabSchedule(t *testing.T) {
	assert.Equal(t, "", getCronTabSchedule(nil))
	assert.Equal(t, "", getCronTabSchedule(&armoapi.Command{}))

	t.Run("from jobParams schedule", func(t *testing.T) {
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"jobParams": armoapi.CronJobParams{JobName: "ks-1", CronTabSchedule: "0 4 * * *"},
			},
		}
		assert.Equal(t, "0 4 * * *", getCronTabSchedule(cmd))
	})

	t.Run("falls back to cronTabSchedule arg when jobParams has empty schedule", func(t *testing.T) {
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"jobParams":       armoapi.CronJobParams{JobName: "ks-1"},
				"cronTabSchedule": "0 5 * * *",
			},
		}
		assert.Equal(t, "0 5 * * *", getCronTabSchedule(cmd))
	})

	t.Run("falls back to designator attribute when jobParams has empty schedule", func(t *testing.T) {
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"kubescapeJobParams": armoapi.CronJobParams{JobName: "ks-1"},
			},
			Designators: []identifiers.PortalDesignator{
				{Attributes: map[string]string{"cronTabSchedule": "0 6 * * *"}},
			},
		}
		assert.Equal(t, "0 6 * * *", getCronTabSchedule(cmd))
	})
}

func TestUpdateKubescapeCronJob(t *testing.T) {
	existing := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "ks-sched-1", Namespace: kubescapeTestNamespace},
		Spec:       batchv1.CronJobSpec{Schedule: "0 1 * * *"},
	}

	t.Run("scheduler disabled returns error", func(t *testing.T) {
		client := fake.NewClientset(existing.DeepCopy())
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"jobParams": armoapi.CronJobParams{JobName: "ks-sched-1", CronTabSchedule: "0 2 * * *"},
			},
		}
		err := kubescapeCronJobHandler(t, false, client, cmd).updateKubescapeCronJob(context.Background())
		require.Error(t, err)
	})

	t.Run("missing jobName returns error", func(t *testing.T) {
		client := fake.NewClientset(existing.DeepCopy())
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"jobParams": armoapi.CronJobParams{CronTabSchedule: "0 2 * * *"},
			},
		}
		err := kubescapeCronJobHandler(t, true, client, cmd).updateKubescapeCronJob(context.Background())
		require.Error(t, err)
	})

	t.Run("missing schedule returns error without clearing existing schedule", func(t *testing.T) {
		client := fake.NewClientset(existing.DeepCopy())
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"jobParams": armoapi.CronJobParams{JobName: "ks-sched-1"},
			},
		}
		err := kubescapeCronJobHandler(t, true, client, cmd).updateKubescapeCronJob(context.Background())
		require.Error(t, err)

		got, getErr := client.BatchV1().CronJobs(kubescapeTestNamespace).Get(context.Background(), "ks-sched-1", metav1.GetOptions{})
		require.NoError(t, getErr)
		assert.Equal(t, "0 1 * * *", got.Spec.Schedule)
	})

	t.Run("updates schedule and jobID annotation", func(t *testing.T) {
		client := fake.NewClientset(existing.DeepCopy())
		cmd := &armoapi.Command{
			JobTracking: armoapi.JobTracking{JobID: "job-999"},
			Args: map[string]interface{}{
				"jobParams":       armoapi.CronJobParams{JobName: "ks-sched-1"},
				"cronTabSchedule": "0 8 * * *",
			},
		}
		err := kubescapeCronJobHandler(t, true, client, cmd).updateKubescapeCronJob(context.Background())
		require.NoError(t, err)

		got, getErr := client.BatchV1().CronJobs(kubescapeTestNamespace).Get(context.Background(), "ks-sched-1", metav1.GetOptions{})
		require.NoError(t, getErr)
		assert.Equal(t, "0 8 * * *", got.Spec.Schedule)
		assert.Equal(t, "job-999", got.Spec.JobTemplate.Spec.Template.Annotations[armotypes.CronJobTemplateAnnotationUpdateJobID])
	})
}

func TestDeleteKubescapeCronJob(t *testing.T) {
	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "ks-sched-1", Namespace: kubescapeTestNamespace},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "ks-sched-1", Namespace: kubescapeTestNamespace},
	}

	t.Run("scheduler disabled returns error", func(t *testing.T) {
		client := fake.NewClientset(cj.DeepCopy(), cm.DeepCopy())
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"jobParams": armoapi.CronJobParams{JobName: "ks-sched-1"},
			},
		}
		require.Error(t, kubescapeCronJobHandler(t, false, client, cmd).deleteKubescapeCronJob(context.Background()))
	})

	t.Run("missing jobName returns error", func(t *testing.T) {
		client := fake.NewClientset(cj.DeepCopy(), cm.DeepCopy())
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"jobParams": armoapi.CronJobParams{},
			},
		}
		require.Error(t, kubescapeCronJobHandler(t, true, client, cmd).deleteKubescapeCronJob(context.Background()))
	})

	t.Run("deletes cronjob and request configmap", func(t *testing.T) {
		client := fake.NewClientset(cj.DeepCopy(), cm.DeepCopy())
		cmd := &armoapi.Command{
			Args: map[string]interface{}{
				"jobParams": armoapi.CronJobParams{JobName: "ks-sched-1"},
			},
		}
		require.NoError(t, kubescapeCronJobHandler(t, true, client, cmd).deleteKubescapeCronJob(context.Background()))

		_, err := client.BatchV1().CronJobs(kubescapeTestNamespace).Get(context.Background(), "ks-sched-1", metav1.GetOptions{})
		assert.True(t, apierrors.IsNotFound(err))
		_, err = client.CoreV1().ConfigMaps(kubescapeTestNamespace).Get(context.Background(), "ks-sched-1", metav1.GetOptions{})
		assert.True(t, apierrors.IsNotFound(err))
	})
}

func TestHandleKubescapeResponse(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		respBody     interface{}
		wantRehandle bool
		wantDelay    time.Duration
	}{
		{
			name:         "busy scan requests rehandle after WaitTimeForKubescapeScanResponse",
			statusCode:   http.StatusOK,
			respBody:     utilsapisv1.Response{ID: "scan-1", Type: utilsapisv1.BusyScanResponseType},
			wantRehandle: true,
			wantDelay:    WaitTimeForKubescapeScanResponse * time.Second,
		},
		{
			name:         "finished scan completes without rehandling",
			statusCode:   http.StatusOK,
			respBody:     utilsapisv1.Response{ID: "scan-1"},
			wantRehandle: false,
		},
		{
			name:         "server error stops rehandling",
			statusCode:   http.StatusInternalServerError,
			respBody:     "internal error",
			wantRehandle: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "scan-1", r.URL.Query().Get("ID"))
				w.WriteHeader(tc.statusCode)
				switch b := tc.respBody.(type) {
				case string:
					_, _ = w.Write([]byte(b))
				default:
					_ = json.NewEncoder(w).Encode(b)
				}
			}))
			defer srv.Close()

			prevClient := KubescapeHttpClient
			KubescapeHttpClient = srv.Client()
			t.Cleanup(func() { KubescapeHttpClient = prevClient })

			cfg, err := config.NewOperatorConfig(
				config.CapabilitiesConfig{},
				utilsmetadata.ClusterConfig{KubescapeURL: strings.TrimPrefix(srv.URL, "http://")},
				&beUtils.Credentials{},
				config.Config{Namespace: kubescapeTestNamespace},
			)
			require.NoError(t, err)

			payload := &kubescapeResponseData{
				scanID:     "scan-1",
				sessionObj: &utils.SessionObj{Command: &armoapi.Command{}},
			}

			rehandle, nextDelay := HandleKubescapeResponse(context.Background(), cfg, payload)
			assert.Equal(t, tc.wantRehandle, rehandle)
			if tc.wantRehandle {
				require.NotNil(t, nextDelay)
				assert.Equal(t, tc.wantDelay, *nextDelay)
			} else {
				assert.Nil(t, nextDelay)
			}
		})
	}
}

package router

import (
	"context"
	"fmt"
	"github.com/openshift/origin/test/extended/router/certgen"
	"net"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	admissionapi "k8s.io/pod-security-admission/api"
	utilpointer "k8s.io/utils/pointer"

	routeclientset "github.com/openshift/client-go/route/clientset/versioned"

	exutil "github.com/openshift/origin/test/extended/util"
	exurl "github.com/openshift/origin/test/extended/util/url"
)

var _ = g.Describe("[sig-network][Feature:Router][apigroup:route.openshift.io]", func() {
	defer g.GinkgoRecover()
	var (
		oc          *exutil.CLI
		ns          string
		routerImage string
		isFIPS      bool
	)

	g.AfterEach(func() {
		if g.CurrentSpecReport().Failed() {
			client := routeclientset.NewForConfigOrDie(oc.AdminConfig()).RouteV1().Routes(ns)
			if routes, _ := client.List(context.Background(), metav1.ListOptions{}); routes != nil {
				outputIngress(routes.Items...)
			}
			selector, err := labels.Parse("test=router-scoped")
			if err != nil {
				panic(err)
			}
			exutil.DumpPodsCommand(oc.AdminKubeClient(), ns, selector, "cat /etc/crypto-policies/back-ends/opensslcnf.config")
			exutil.DumpPodLogsStartingWith("router-", oc)
		}
	})

	oc = exutil.NewCLIWithPodSecurityLevel("router-certs", admissionapi.LevelBaseline)

	g.BeforeEach(func() {
		ns = oc.Namespace()

		var err error
		routerImage, err = exutil.FindRouterImage(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		isFIPS, err = exutil.IsFIPS(oc.AdminKubeClient().CoreV1())
		o.Expect(err).NotTo(o.HaveOccurred())

		configPath := exutil.FixturePath("testdata", "router", "router-common.yaml")
		err = oc.AsAdmin().Run("apply").Args("-f", configPath).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.When("FIPS is enabled", func() {
		g.Describe("the HAProxy router", func() {
			g.It("should not work when configured with a 1024-bit RSA key", func() {
				if !isFIPS {
					g.Skip("skipping on non-FIPS cluster")
				}

				pemData1024, err := generateRouterPem(1024)
				o.Expect(err).NotTo(o.HaveOccurred())

				routerPod := createScopedRouterPod(routerImage, "test-1024bit", pemData1024, "true")
				g.By("creating a router")
				ns := oc.KubeFramework().Namespace.Name
				_, err = oc.AdminKubeClient().CoreV1().Pods(ns).Create(context.Background(), routerPod, metav1.CreateOptions{})
				o.Expect(err).NotTo(o.HaveOccurred())

				execPod := exutil.CreateExecPodOrFail(oc.AdminKubeClient(), ns, "execpod")
				defer func() {
					oc.AdminKubeClient().CoreV1().Pods(ns).Delete(context.Background(), execPod.Name, *metav1.NewDeleteOptions(1))
				}()

				var routerIP string
				err = wait.Poll(time.Second, changeTimeoutSeconds*time.Second, func() (bool, error) {
					pod, err := oc.KubeFramework().ClientSet.CoreV1().Pods(oc.KubeFramework().Namespace.Name).Get(context.Background(), "router-scoped", metav1.GetOptions{})
					if err != nil {
						return false, err
					}
					routerIP = pod.Status.PodIP
					podIsReady := podConditionStatus(pod, corev1.PodReady)

					return len(routerIP) != 0 && podIsReady == corev1.ConditionTrue, nil
				})
				o.Expect(err).To(o.HaveOccurred())
			})
		})
	})

	g.When("FIPS is disabled", func() {
		g.Describe("the HAProxy router", func() {
			g.It("should serve routes when configured with a 1024-bit RSA key", func() {
				if isFIPS {
					g.Skip("skipping on FIPS cluster")
				}

				pemData1024, err := generateRouterPem(1024)
				o.Expect(err).NotTo(o.HaveOccurred())

				routerPod := createScopedRouterPod(routerImage, "test-1024bit", pemData1024, "true")
				g.By("creating a router")
				ns := oc.KubeFramework().Namespace.Name
				_, err = oc.AdminKubeClient().CoreV1().Pods(ns).Create(context.Background(), routerPod, metav1.CreateOptions{})
				o.Expect(err).NotTo(o.HaveOccurred())

				execPod := exutil.CreateExecPodOrFail(oc.AdminKubeClient(), ns, "execpod")
				defer func() {
					oc.AdminKubeClient().CoreV1().Pods(ns).Delete(context.Background(), execPod.Name, *metav1.NewDeleteOptions(1))
				}()

				var routerIP string
				err = wait.Poll(time.Second, changeTimeoutSeconds*time.Second, func() (bool, error) {
					pod, err := oc.KubeFramework().ClientSet.CoreV1().Pods(oc.KubeFramework().Namespace.Name).Get(context.Background(), "router-scoped", metav1.GetOptions{})
					if err != nil {
						return false, err
					}
					routerIP = pod.Status.PodIP
					podIsReady := podConditionStatus(pod, corev1.PodReady)

					return len(routerIP) != 0 && podIsReady == corev1.ConditionTrue, nil
				})
				o.Expect(err).NotTo(o.HaveOccurred())

				g.By("waiting for the router's healthz endpoint to respond")
				healthzURI := fmt.Sprintf("http://%s/healthz", net.JoinHostPort(routerIP, "1936"))
				healthzt := exurl.NewTester(oc.AdminKubeClient(), ns).WithErrorPassthrough(true)
				defer healthzt.Close()
				healthzt.Within(
					time.Minute,
					exurl.Expect("GET", healthzURI).SkipTLSVerification().HasStatusCode(200),
				)

				g.By("waiting for the route to respond")
				url := "https://first.example.com/Letter"
				t := exurl.NewTester(oc.AdminKubeClient(), ns).WithErrorPassthrough(true)
				defer t.Close()
				t.Within(
					time.Minute,
					exurl.Expect("GET", url).Through(routerIP).SkipTLSVerification().HasStatusCode(200),
				)
			})
		})
	})
})

// generateRouterPem generates a "default" certificate
// usable by the router, given the number bits for the
// RSA key algorithm.
func generateRouterPem(keyBits int) (string, error) {
	// certificate start and end time are very
	// lenient to avoid any clock drift between
	// the test machine and the cluster under test.
	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	_, tlsCrtData, tlsPrivateKey, err := certgen.GenerateRSAKeyPair(notBefore, notAfter, keyBits, "www.exampleca.com")
	if err != nil {
		return "", err
	}
	defaultPemData, err := certgen.MarshalCertToPEMString(tlsCrtData)
	if err != nil {
		return "", err
	}

	derKey, err := certgen.MarshalRSAPrivateKeyToDERFormat(tlsPrivateKey)
	o.Expect(err).NotTo(o.HaveOccurred())

	return defaultPemData + derKey, err
}

func createScopedRouterPod(routerImage, routerName, pemData, updateStatus string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "router-scoped",
			Labels: map[string]string{
				"test": "router-scoped",
			},
		},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: utilpointer.Int64(1),
			Containers: []corev1.Container{
				{
					Name:            "route",
					Image:           routerImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Env: []corev1.EnvVar{
						{
							Name: "POD_NAMESPACE",
							ValueFrom: &corev1.EnvVarSource{
								FieldRef: &corev1.ObjectFieldSelector{
									FieldPath: "metadata.namespace",
								},
							},
						},
						{
							Name:  "DEFAULT_CERTIFICATE",
							Value: pemData,
						},
					},
					Args: []string{
						"--name=" + routerName,
						"--namespace=$(POD_NAMESPACE)",
						"--update-status=" + updateStatus,
						"-v=4",
						"--labels=select=first",
						"--stats-port=1936",
						"--metrics-type=haproxy",
					},
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 80,
						},
						{
							ContainerPort: 443,
						},
						{
							ContainerPort: 1936,
							Name:          "stats",
							Protocol:      corev1.ProtocolTCP,
						},
					},
					ReadinessProbe: &corev1.Probe{
						InitialDelaySeconds: 10,
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path: "/healthz/ready",
								Port: intstr.FromInt(1936),
							},
						},
					},
				},
			},
		},
	}
}

# Exposed secrets

Secrets the Trivy Operator found in image layers: keys, tokens and private keys baked into an image. Each row shows the severity, what kind of secret it is, the file inside the image, the image and the workload running it.

Gjallarhorn never reads the matched text from the report, so it cannot show it, even partly masked. Open the file in the image to see what was found.

Many findings are example or test files shipped with an application. They still end up in every copy of the image, so check them.

The scanner is controlled by `operator.exposedSecretScannerEnabled` in the Trivy Operator chart.

// Embedded production Psiphon network parameters, used when the provider runs
// with no config_path: they make the plugin work out of the box, exactly like
// the official client does on first run. With these values tunnel-core's
// RemoteServerListFetcher downloads the signed server list from the production
// URLs, verifies it against defaultRemoteServerListSignaturePublicKey
// (entries against defaultServerEntrySignaturePublicKey), and establishes a
// tunnel — no local psiphon.config or server_list.dat needed.
//
// The values were extracted from the official psiphon3.exe Windows client
// (psiphon.ca, unpacked from UPX) and the RSA signing key was verified
// cryptographically against the live production server list: the package
// digest (sha256 of the base64 key string) in the downloaded
// AuthenticatedDataPackage selects this key, and its signature verifies with
// RSA PKCS1v15 over the sha256 of the hex-encoded payload string — the exact
// scheme psiphon/common/authPackage.go implements. A config_path supplied by
// the user overrides all of this (custom networks).
package psiphon

import "encoding/json"

const (
	// defaultPropagationChannelId / defaultSponsorId identify the production
	// Psiphon network the official Windows client uses.
	defaultPropagationChannelId = "92AACC5BABE0944C"
	defaultSponsorId            = "1BC527D3D09985CF"
)

// defaultRemoteServerListURLsJSON lists the production remote server list
// endpoints (S3 primary + fronted fallbacks, each base64-obfuscated with a
// transfer strategy, as tunnel-core's parameters.TransferURLs expects).
const defaultRemoteServerListURLsJSON = `[{"URL": "aHR0cHM6Ly9zMy5hbWF6b25hd3MuY29tL3BzaXBob24vd2ViL21qcjQtcDIzci1wdXdsL3NlcnZlcl9saXN0X2NvbXByZXNzZWQ=", "OnlyAfterAttempts": 0, "SkipVerify": false}, {"URL": "aHR0cHM6Ly93d3cucmFjZWVnZ3V4ZGFzLmNvbS93ZWIvbWpyNC1wMjNyLXB1d2wvc2VydmVyX2xpc3RfY29tcHJlc3NlZA==", "OnlyAfterAttempts": 2, "SkipVerify": true}, {"URL": "aHR0cHM6Ly93d3cuc3lzdGVtc2FmYXJpdW5pdmVyc2l0eWRlYnQuY29tL3dlYi9tanI0LXAyM3ItcHV3bC9zZXJ2ZXJfbGlzdF9jb21wcmVzc2Vk", "OnlyAfterAttempts": 2, "SkipVerify": true}, {"URL": "aHR0cHM6Ly93d3cuYmxvZ3NmbWNhbmNlcmNpdGl6ZW4uY29tL3dlYi9tanI0LXAyM3ItcHV3bC9zZXJ2ZXJfbGlzdF9jb21wcmVzc2Vk", "OnlyAfterAttempts": 2, "SkipVerify": true}]`

// defaultObfuscatedServerListRootURLsJSON lists the production obfuscated
// server list roots, same encoding.
const defaultObfuscatedServerListRootURLsJSON = `[{"URL": "aHR0cHM6Ly9zMy5hbWF6b25hd3MuY29tL3BzaXBob24vd2ViL21qcjQtcDIzci1wdXdsL29zbA==", "OnlyAfterAttempts": 0, "SkipVerify": false}, {"URL": "aHR0cHM6Ly93d3cucmFjZWVnZ3V4ZGFzLmNvbS93ZWIvbWpyNC1wMjNyLXB1d2wvb3Ns", "OnlyAfterAttempts": 2, "SkipVerify": true}, {"URL": "aHR0cHM6Ly93d3cuc3lzdGVtc2FmYXJpdW5pdmVyc2l0eWRlYnQuY29tL3dlYi9tanI0LXAyM3ItcHV3bC9vc2w=", "OnlyAfterAttempts": 2, "SkipVerify": true}, {"URL": "aHR0cHM6Ly93d3cuYmxvZ3NmbWNhbmNlcmNpdGl6ZW4uY29tL3dlYi9tanI0LXAyM3ItcHV3bC9vc2w=", "OnlyAfterAttempts": 2, "SkipVerify": true}]`

// defaultRemoteServerListSignaturePublicKey (RSA) signs the remote server
// list; verified against the live production list.
const defaultRemoteServerListSignaturePublicKey = `MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=`

// defaultServerEntrySignaturePublicKey (ed25519) signs handshake-discovered
// server entries.
const defaultServerEntrySignaturePublicKey = `sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA=`

// defaultClientVersion mirrors the current official Windows client release.
const defaultClientVersion = "189"

// defaultConfig synthesizes the psiphon.config tunnel-core consumes: the
// required channel/sponsor/version fields plus the signed remote server list
// endpoints and their verification keys. ClientPlatform, NetworkID, and the
// data root are injected by the provider as clientlib Parameters (and are
// stripped by sanitizeConfig anyway).
type defaultConfig struct {
	PropagationChannelId               string          `json:"PropagationChannelId"`
	SponsorId                          string          `json:"SponsorId"`
	ClientVersion                      string          `json:"ClientVersion"`
	RemoteServerListURLs               json.RawMessage `json:"RemoteServerListURLs"`
	RemoteServerListSignaturePublicKey string          `json:"RemoteServerListSignaturePublicKey"`
	ObfuscatedServerListRootURLs       json.RawMessage `json:"ObfuscatedServerListRootURLs"`
	ServerEntrySignaturePublicKey      string          `json:"ServerEntrySignaturePublicKey"`
}

// defaultConfigJSON returns the marshaled zero-config psiphon.config.
func defaultConfigJSON() []byte {
	cfg := defaultConfig{
		PropagationChannelId:               defaultPropagationChannelId,
		SponsorId:                          defaultSponsorId,
		ClientVersion:                      defaultClientVersion,
		RemoteServerListURLs:               json.RawMessage(defaultRemoteServerListURLsJSON),
		RemoteServerListSignaturePublicKey: defaultRemoteServerListSignaturePublicKey,
		ObfuscatedServerListRootURLs:       json.RawMessage(defaultObfuscatedServerListRootURLsJSON),
		ServerEntrySignaturePublicKey:      defaultServerEntrySignaturePublicKey,
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		// All inputs are constants; marshaling cannot fail. Fall back to a
		// minimal but still-valid config if it somehow does.
		return []byte(`{"PropagationChannelId":"` + defaultPropagationChannelId +
			`","SponsorId":"` + defaultSponsorId + `","ClientVersion":"` + defaultClientVersion +
			`"}`)
	}
	return b
}

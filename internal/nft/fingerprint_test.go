package nft

import "testing"

func TestCanonicalFingerprintIgnoresOnlyVolatileState(t *testing.T) {
	table := Table{Family: "inet", Name: "nftfw_filter"}
	first := []byte(`{"nftables":[{"metainfo":{"version":"1"}},{"table":{"family":"inet","name":"nftfw_filter","handle":1}},{"set":{"family":"inet","table":"nftfw_filter","name":"blocked_v4","handle":2,"type":"ipv4_addr","elem":["203.0.113.1"]}},{"rule":{"family":"inet","table":"nftfw_filter","chain":"input","handle":3,"comment":"nftfw:block-v4","expr":[{"counter":{"packets":1,"bytes":64}},{"drop":null}]}}]}`)
	second := []byte(`{"nftables":[{"metainfo":{"version":"2"}},{"table":{"family":"inet","name":"nftfw_filter","handle":91}},{"set":{"family":"inet","table":"nftfw_filter","name":"blocked_v4","handle":92,"type":"ipv4_addr","elem":["198.51.100.2"]}},{"rule":{"family":"inet","table":"nftfw_filter","chain":"input","handle":93,"comment":"nftfw:block-v4","expr":[{"counter":{"packets":900,"bytes":9000}},{"drop":null}]}}]}`)
	a, err := canonicalOwnedJSON(first, table)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalOwnedJSON(second, table)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("volatile state changed fingerprint:\n%s\n%s", a, b)
	}

	tampered := []byte(`{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"set":{"family":"inet","table":"nftfw_filter","name":"blocked_v4","type":"ipv4_addr"}},{"rule":{"family":"inet","table":"nftfw_filter","chain":"input","comment":"nftfw:block-v4","expr":[{"counter":{}},{"accept":null}]}}]}`)
	c, err := canonicalOwnedJSON(tampered, table)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(c) {
		t.Fatal("marker-preserving verdict tampering was ignored")
	}
}

func TestCanonicalFingerprintRejectsForeignObjects(t *testing.T) {
	_, err := canonicalOwnedJSON([]byte(`{"nftables":[{"table":{"family":"inet","name":"other"}}]}`), Table{Family: "inet", Name: "nftfw_filter"})
	if err == nil {
		t.Fatal("foreign table object accepted")
	}
}

func FuzzCanonicalOwnedJSON(f *testing.F) {
	f.Add([]byte(`{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = canonicalOwnedJSON(data, Table{Family: "inet", Name: "nftfw_filter"})
	})
}

package proto

import (
	"sync"
	"testing"
)

// Registration overlaps background status polling in in-process E2E clients.
func TestPQRegistryConcurrentStatus(t *testing.T) {
	pqRegistryMu.RLock()
	previousProvider, previousName := pqProvider, pqBackendName
	pqRegistryMu.RUnlock()
	defer func() { RegisterPQProvider(previousProvider); SetPQBackendName(previousName) }()
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 200; iteration++ {
				RegisterPQProvider(func(PQSignatureAlgorithm) (PQVerifier, bool) { return nil, false })
				SetPQBackendName("concurrent-test")
				_ = PQIdentityAvailable()
				_ = PQBackendName()
				_, _ = PQVerifierFor(PQSigMLDSA65)
			}
		}()
	}
	workers.Wait()
}

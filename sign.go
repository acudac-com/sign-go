package sign

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/acudac-com/blob-go"
	"github.com/golang-jwt/jwt"
	"go.alis.build/alog"
	"google.golang.org/grpc/metadata"
)

const BlobPrefix = ".keys"

// Provides functions to create and validate jwts.
// Uses Google Cloud Storage to store the 2048 bit private RSA keys.
type Signer[T jwt.Claims] struct {
	blobStorage blob.Storage
	cachedKeys  *sync.Map
	newClaims   func() T
}

// Returns a new Signer to create and validate jwt tokens. The signer will store
// the RSA keys in the ".keys/" folder of the provided blob storage.
func NewSigner[T jwt.Claims](blobStorage blob.Storage, newClaims func() T) (*Signer[T], error) {
	gcsJwt := &Signer[T]{
		blobStorage: blobStorage,
		cachedKeys:  &sync.Map{},
		newClaims:   newClaims,
	}
	go func() {
		ctx := context.Background()
		if _, err := gcsJwt.PublicKeys(ctx); err != nil {
			alog.Fatalf(ctx, "failed to initialize keys: %v", err)
		}
	}()
	return gcsJwt, nil
}

// Returns a signed jwt token with the provided claims.
func (s *Signer[T]) Sign(ctx context.Context, claims T) (string, error) {
	// get the private key
	keyId := time.Now().UTC().Format("2006-01-02")
	keys, err := s.rsaKeys(ctx, []string{keyId})
	if err != nil {
		return "", err
	}

	// create new unsigned jwt token with provided claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyId

	// Sign the token with the private key
	signedJwt, err := token.SignedString(keys[0])
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedJwt, nil
}

// Returns the two public keys currently in rotation.
func (s *Signer[T]) PublicKeys(ctx context.Context) ([]*PublicKey, error) {
	// determine which key ids to get based on today and yesterday
	today := time.Now().UTC()
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	yesterday := today.AddDate(0, 0, -1)
	todayKeyId := today.Format("2006-01-02")
	yesterdayKeyId := yesterday.Format("2006-01-02")
	keyIds := []string{todayKeyId, yesterdayKeyId}

	// get the rsa private keys
	keys, err := s.rsaKeys(ctx, keyIds)
	if err != nil {
		return nil, err
	}

	// convert to public keys
	publicKeys := []*PublicKey{}
	for i, key := range keys {
		publicKeyPem := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
		}
		PublicKey := &PublicKey{
			Kid: keyIds[i],
			Key: string(pem.EncodeToMemory(publicKeyPem)),
		}
		publicKeys = append(publicKeys, PublicKey)
	}
	return publicKeys, nil
}

// Returns the jwt claims if validation succeeds.
// Fails if the signedJwt has the incorrect signature or is expired.
// Strips out any 'bearer ' or 'Bearer ' prefix
func (s *Signer[T]) Parse(ctx context.Context, signedJwt string) T {
	signedJwt = strings.TrimPrefix(signedJwt, "bearer ")
	signedJwt = strings.TrimPrefix(signedJwt, "Bearer ")
	claims := s.newClaims()
	t, err := jwt.ParseWithClaims(signedJwt, s.newClaims(), func(token *jwt.Token) (interface{}, error) {
		// get kid from headers
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found")
		}

		// fail if kid not today or yesterday's key
		todayUtc := time.Now().UTC()
		todayKey := todayUtc.Format("2006-01-02")
		yesterdayKey := todayUtc.AddDate(0, 0, -1).Format("2006-01-02")
		if kid != todayKey && kid != yesterdayKey {
			return nil, fmt.Errorf("invalid key id")
		}

		// find key for validation
		key, err := s.rsaKeys(ctx, []string{kid})
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}
		return &key[0].PublicKey, nil
	})
	if err != nil {
		alog.Errorf(ctx, "parsing %s: %v", signedJwt, err)
		return claims
	} else if claims, ok := t.Claims.(T); ok {
		return claims
	} else {
		alog.Errorf(ctx, "parsing claims for %s", signedJwt)
		return claims
	}
}

// Returns the jwt claims if validation succeeds.
// Fails if the signedJwt has the incorrect signature or is expired.
// Strips out any 'bearer ' or 'Bearer ' prefix
// Returns an empty claims, instead of an error, if the provided key is not found in the incoming ctx.
func (s *Signer[T]) ParseCtx(ctx context.Context, key string) T {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return s.newClaims()
	}
	vals := md.Get(key)
	if len(vals) == 0 {
		return s.newClaims()
	}
	return s.Parse(ctx, vals[0])
}

// Returns the jwt claims if validation succeeds.
// Fails if the signedJwt has the incorrect signature or is expired.
// Strips out any 'bearer ' or 'Bearer ' prefix
// Returns an empty claims, instead of an error, if the provided header is not found in the incoming ctx.
func (s *Signer[T]) ParseHeader(req *http.Request, headerKey string) T {
	header := req.Header.Get(headerKey)
	if header == "" {
		return s.newClaims()
	}
	return s.Parse(req.Context(), header)
}

func (s *Signer[T]) ParseCookie(req *http.Request, cookieKey string) T {
	cookie, err := req.Cookie(cookieKey)
	if err != nil {
		return s.newClaims()
	}
	if cookie == nil || cookie.Value == "" {
		return s.newClaims()
	}
	return s.Parse(req.Context(), cookie.Value)
}

// Returns the rsa private keys for the given key ids. If the key does not exist, it will be created.
func (s *Signer[T]) rsaKeys(ctx context.Context, keyIds []string) ([]*rsa.PrivateKey, error) {
	keys := []*rsa.PrivateKey{}
	for _, keyId := range keyIds {
		// return from cache if exists
		if key, ok := s.cachedKeys.Load(keyId); ok {
			keys = append(keys, key.(*rsa.PrivateKey))
			continue
		}

		// read from storage
		keyPath := path.Join(BlobPrefix, keyId)
		keyBytes, err := s.blobStorage.Read(ctx, keyPath)
		if err == nil {
			block, _ := pem.Decode(keyBytes)
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
			s.cachedKeys.Store(keyId, key)
			keys = append(keys, key)
			continue
		} else {
			// create new rsa private key
			privKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, fmt.Errorf("failed to generate private key: %w", err)
			}

			// determine PEM encoded rsa private key
			keyBytes = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privKey),
			})

			// upload if does not yet exist
			err = s.blobStorage.WriteIfMissing(ctx, keyPath, keyBytes)
			if err != nil {
				// if failed to write, try to read again
				keyBytes, err = s.blobStorage.Read(ctx, keyPath)
				if err != nil {
					return nil, fmt.Errorf("failed to read private key: %w", err)
				}

				// parse the key
				block, _ := pem.Decode(keyBytes)
				privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse private key: %w", err)
				}
			}

			// add to cache and list of keys
			s.cachedKeys.Store(keyId, privKey)
			keys = append(keys, privKey)
			continue
		}
	}
	return keys, nil
}

// PublicKey represents a public key
type PublicKey struct {
	// Key ID
	Kid string
	// PEM encoded public key
	Key string
}

func (p *PublicKey) String() string {
	return fmt.Sprintf("Kid: %s, Key: %s", p.Kid, p.Key)
}

package cmd

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dimfeld/httptreemux"
	"github.com/spf13/cobra"
)

func init() {
	cmd := &cobra.Command{
		Use:     "serve [db file]",
		Short:   "Start Have I Been Pwned password API",
		Example: "serve pwned-passwords.db",
		Run:     serve,
		Args:    cobra.ExactArgs(1),
	}

	cmd.Flags().String("listen", "localhost:8080", "address to listen")

	rootCmd.AddCommand(cmd)
}

type Server struct {
	addresses []uint32
	db        io.ReaderAt
}

func serve(cmd *cobra.Command, args []string) {
	listen := cmd.Flags().Lookup("listen").Value.String()

	db, err := os.Open(args[0])
	if err != nil {
		log.Fatal("Failed to open database: ", err.Error())
	}

	addresses := make([]uint32, addrMapSize, addrMapSize)
	err = binary.Read(db, binary.LittleEndian, addresses)
	if err != nil {
		log.Fatal("Failed to read offsets header: ", err.Error())
	}

	s := &Server{
		db:        db,
		addresses: addresses,
	}

	router := httptreemux.NewContextMux()
	router.GET("/api/range/:prefix", s.fetchPrefix)

	log.Printf("Starting server, listening on %q", listen)
	log.Fatal(http.ListenAndServe(listen, router))
}

func (s *Server) fetchPrefix(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Parse prefix
	prefixString := httptreemux.ContextParams(r.Context())["prefix"]
	if len(prefixString) != 6 {
		http.Error(w, "prefix should be the first 6 characters of the SHA-1 password", http.StatusBadRequest)
		return
	}

	prefix, err := strconv.ParseUint(prefixString, 16, 32)
	if err != nil {
		http.Error(w, "prefix should be the first 6 characters of the SHA-1 password", http.StatusBadRequest)
		return
	}

	// Look up offsets
	startOffset := s.addresses[prefix]
	endOffset := s.addresses[prefix+1]
	len := endOffset - startOffset

	// Read hashes
	hashes := make([]byte, 17*(len))
	s.db.ReadAt(hashes, 4*addrMapSize+int64(startOffset)*17)

	// Encode result to strings
	hashesHex := make([]string, (len))
	for i := 0; i < int(len); i++ {
		hashesHex[i] = hex.EncodeToString(hashes[i*17 : (i+1)*17])
	}

	// And to JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hashesHex)

	log.Printf("Prefix %06x fetched, duration: %s", prefix, time.Since(start))
}

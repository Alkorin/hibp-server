package cmd

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"log"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"go4.org/strutil"
)

func init() {
	cmd := &cobra.Command{
		Use:     "generate [ordered-by-hash.txt file] [db file]",
		Short:   "Generate lookup database from ordered-by-hash txt file",
		Example: "generate pwned-passwords-ordered-by-hash.txt pwned-passwords.db",
		Run: func(cmd *cobra.Command, args []string) {
			err := generateDB(args[0], args[1])
			if err != nil {
				log.Fatal(err)
			}
		},
		Args: cobra.ExactArgs(2),
	}

	rootCmd.AddCommand(cmd)
}

func generateDB(src string, dst string) error {
	log.Printf("Generating DB %q from %q...", dst, src)

	// Open file (sorted by hash)
	file, err := os.Open(src)
	if err != nil {
		return errors.Wrap(err, "Failed to open source file")
	}
	defer file.Close()

	// Open output db file
	db, err := os.Create(dst)
	if err != nil {
		return errors.Wrap(err, "Failed to open destination file")
	}
	defer db.Close()

	// Create addr map
	addresses := make([]uint32, addrMapSize, addrMapSize)

	// First part of the file will be the prefix address map
	_, err = db.Seek(int64(binary.Size(addresses)), 0)
	if err != nil {
		return errors.Wrap(err, "Failed to write header")
	}

	// Initial values
	currentOffset := uint32(0)
	previousPrefix := uint64(0)
	timerTime := time.Now()
	timerOffset := currentOffset

	// Temporary storage for unhexed hash (avoid alloc)
	hash := make([]byte, 17)

	// Initialize huge buffers to speedup I/O
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 16*1024*1024), 16*1024*1024)
	writer := bufio.NewWriterSize(db, 16*1024*1024)

	// Read each line of source file, write hash and update address map if needed
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) < 40 {
			return errors.Errorf("Failed to parse line %q", line)
		}

		// Read prefix
		prefix, err := strutil.ParseUintBytes(line[0:6], 16, 32)
		if err != nil {
			return errors.Errorf("Failed to parse prefix from line %q", line)
		}

		// Update address map if needed
		if prefix != previousPrefix {
			for k := previousPrefix + 1; k <= prefix; k++ {
				addresses[k] = currentOffset
			}
			previousPrefix = prefix
		}

		// Write hash value
		_, err = hex.Decode(hash, line[6:40])
		if err != nil {
			return errors.Errorf("Failed to decode hash from line %q", line)
		}
		writer.Write(hash)

		// Update offset
		currentOffset += 1

		// Show some statistics
		if time.Since(timerTime) > 10*time.Second {
			log.Printf("Parsed %d hashes, total: %d", currentOffset-timerOffset, currentOffset)
			timerOffset = currentOffset
			timerTime = time.Now()
		}
	}
	writer.Flush()

	// Fill end of map
	for k := previousPrefix + 1; k <= addrMapSize-1; k++ {
		addresses[k] = currentOffset
	}

	// Write prefix address map at the beginning of the file
	db.Seek(0, 0)
	binary.Write(db, binary.LittleEndian, addresses)

	// Done
	log.Printf("DB generated, contains %d hashes", currentOffset)
	return nil
}

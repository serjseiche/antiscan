package service

import (
	"testing"
)

func TestParseIpsetEntries(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{
			name: "normal output",
			input: `Name: SCANNERS-BLOCK-V4
Type: hash:net
Revision: 7
Header: family inet hashsize 1024 maxelem 65536
Size in memory: 408
References: 1
Number of entries: 42
`,
			want: 42,
		},
		{
			name: "zero entries",
			input: `Name: SCANNERS-BLOCK-V4
Type: hash:net
Number of entries: 0
`,
			want: 0,
		},
		{
			name: "leading spaces around value",
			input: `Number of entries:   1337
`,
			want: 1337,
		},
		{
			name:    "missing line",
			input:   "Name: SCANNERS-BLOCK-V4\nType: hash:net\n",
			wantErr: true,
		},
		{
			name:    "non-numeric value",
			input:   "Number of entries: abc\n",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIpsetEntries(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %d)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseDropPackets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{
			name: "single DROP rule",
			input: `Chain SCANNERS-BLOCK (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      42     2520 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set SCANNERS-BLOCK-V4 src
`,
			want: 42,
		},
		{
			name: "multiple DROP rules summed",
			input: `Chain SCANNERS-BLOCK (1 references)
 pkts bytes target prot opt in out source destination
  100  6000 DROP   all  --  *  *  0.0.0.0/0  0.0.0.0/0
  200 12000 DROP   all  --  *  *  0.0.0.0/0  0.0.0.0/0
`,
			want: 300,
		},
		{
			name: "RETURN line not counted",
			input: `Chain SCANNERS-BLOCK (1 references)
 pkts bytes target prot opt in out source destination
  999  1000 RETURN all  --  *  *  0.0.0.0/0  0.0.0.0/0
   55  3300 DROP   all  --  *  *  0.0.0.0/0  0.0.0.0/0
`,
			want: 55,
		},
		{
			name:  "empty output",
			input: "",
			want:  0,
		},
		{
			name: "zero packets",
			input: `Chain SCANNERS-BLOCK (1 references)
 pkts bytes target prot opt in out source destination
    0     0 DROP   all  --  *  *  0.0.0.0/0  0.0.0.0/0
`,
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDropPackets(tc.input)
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

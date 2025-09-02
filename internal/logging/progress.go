package logger

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ProgressBar represents a simple progress bar
type ProgressBar struct {
	prefix     string
	total      int
	current    int
	width      int
	startTime  time.Time
	lastUpdate time.Time
	completed  bool
}

// NewProgressBar creates a new progress bar
func NewProgressBar(prefix string, total int) *ProgressBar {
	return &ProgressBar{
		prefix:    prefix,
		total:     total,
		width:     40,
		startTime: time.Now(),
	}
}

// Update increments the progress bar
func (pb *ProgressBar) Update(current int) {
	pb.current = current
	if time.Since(pb.lastUpdate) < 100*time.Millisecond && current < pb.total {
		return // Avoid too frequent updates
	}
	pb.lastUpdate = time.Now()
	pb.render()
}

// Complete marks the progress bar as finished
func (pb *ProgressBar) Complete() {
	pb.current = pb.total
	pb.completed = true
	pb.render()
	fmt.Print("\n")
}

// render draws the progress bar
func (pb *ProgressBar) render() {
	percent := float64(pb.current) / float64(pb.total)
	if percent > 1 {
		percent = 1
	}

	filled := int(percent * float64(pb.width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", pb.width-filled)

	elapsed := time.Since(pb.startTime)
	var timeInfo string
	if pb.completed {
		timeInfo = fmt.Sprintf(" ✓ %v", elapsed.Round(time.Second))
	} else if pb.current > 0 {
		eta := time.Duration(float64(elapsed) * (float64(pb.total)/float64(pb.current) - 1))
		timeInfo = fmt.Sprintf(" %v/%v ETA %v", elapsed.Round(time.Second),
			(elapsed + eta).Round(time.Second), eta.Round(time.Second))
	}

	fmt.Printf("\r%s [%s] %d/%d%s", pb.prefix, bar, pb.current, pb.total, timeInfo)
}

// Spinner represents a simple spinner for indeterminate progress
type Spinner struct {
	prefix    string
	frames    []string
	current   int
	running   bool
	startTime time.Time
	done      chan bool
}

// NewSpinner creates a new spinner
func NewSpinner(prefix string) *Spinner {
	return &Spinner{
		prefix:    prefix,
		frames:    []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		startTime: time.Now(),
		done:      make(chan bool),
	}
}

// Start begins the spinner animation
func (s *Spinner) Start() {
	s.running = true
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				if s.running {
					s.render()
					s.current = (s.current + 1) % len(s.frames)
				}
			}
		}
	}()
}

// Stop ends the spinner
func (s *Spinner) Stop(message string) {
	s.running = false
	s.done <- true
	elapsed := time.Since(s.startTime)
	fmt.Printf("\r%s ✓ %s (%v)\n", s.prefix, message, elapsed.Round(time.Second))
}

// render draws the current spinner frame
func (s *Spinner) render() {
	elapsed := time.Since(s.startTime)
	fmt.Printf("\r%s %s %v", s.prefix, s.frames[s.current], elapsed.Round(time.Second))
}

// PrintHeader prints a formatted section header
func PrintHeader(title string) {
	width := 60
	padding := (width - len(title) - 2) / 2
	border := strings.Repeat("═", width)
	spacer := strings.Repeat(" ", padding)

	fmt.Printf("\n%s\n", border)
	fmt.Printf("║%s %s %s║\n", spacer, title, spacer)
	fmt.Printf("%s\n\n", border)
}

// PrintSubHeader prints a formatted subsection header
func PrintSubHeader(title string) {
	fmt.Printf("┌─ %s\n", title)
}

// PrintSuccess prints a success message
func PrintSuccess(message string) {
	fmt.Printf("✓ %s\n", message)
}

// PrintWarning prints a warning message
func PrintWarning(message string) {
	fmt.Printf("⚠ %s\n", message)
}

// PrintError prints an error message
func PrintError(message string) {
	fmt.Printf("✗ %s\n", message)
}

// PrintInfo prints an info message
func PrintInfo(message string) {
	fmt.Printf("• %s\n", message)
}

// Table represents a simple table for displaying data
type Table struct {
	headers []string
	rows    [][]string
	widths  []int
}

// NewTable creates a new table
func NewTable(headers ...string) *Table {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	return &Table{
		headers: headers,
		widths:  widths,
	}
}

// AddRow adds a row to the table
func (t *Table) AddRow(values ...string) {
	if len(values) != len(t.headers) {
		return
	}

	// Update column widths
	for i, v := range values {
		if len(v) > t.widths[i] {
			t.widths[i] = len(v)
		}
	}

	t.rows = append(t.rows, values)
}

// Print displays the table
func (t *Table) Print() {
	if len(t.rows) == 0 {
		return
	}

	// Print separator
	t.printSeparator("┌", "┬", "┐")

	// Print headers
	t.printRow(t.headers)
	t.printSeparator("├", "┼", "┤")

	// Print rows
	for _, row := range t.rows {
		t.printRow(row)
	}

	// Print bottom separator
	t.printSeparator("└", "┴", "┘")
	fmt.Println()
}

// printSeparator prints a table separator line
func (t *Table) printSeparator(left, middle, right string) {
	fmt.Print(left)
	for i, width := range t.widths {
		fmt.Print(strings.Repeat("─", width+2))
		if i < len(t.widths)-1 {
			fmt.Print(middle)
		}
	}
	fmt.Println(right)
}

// printRow prints a table row
func (t *Table) printRow(values []string) {
	fmt.Print("│")
	for i, value := range values {
		fmt.Printf(" %-*s │", t.widths[i], value)
	}
	fmt.Println()
}

// Clear clears the terminal screen
func Clear() {
	fmt.Print("\033[2J\033[H")
}

// HideCursor hides the terminal cursor
func HideCursor() {
	fmt.Print("\033[?25l")
}

// ShowCursor shows the terminal cursor
func ShowCursor() {
	fmt.Print("\033[?25h")
}

// QuietExecute runs a function while capturing and suppressing its output
func QuietExecute(fn func() error) error {
	// Temporarily redirect stdout/stderr to discard
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	// Create temporary files to capture output
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	// Run the function
	err := fn()

	// Restore stdout/stderr
	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	// Discard captured output
	go func() {
		for {
			buffer := make([]byte, 1024)
			_, readErr := r.Read(buffer)
			if readErr != nil {
				break
			}
		}
		r.Close()
	}()

	return err
}

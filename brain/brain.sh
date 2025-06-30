#!/bin/bash

BRAIN_FILE="${BRAIN_FILE:-$HOME/.brain}"

store_entry() {
    local text=""
    local keywords=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --text)
                shift; text="$1"
                ;;
            --keywords)
                shift; keywords="$1"
                ;;
        esac
        shift
    done

    # Ask user if no arguments provided
    if [[ -z "$text" ]]; then
        echo "Enter the text to store:"
        read -r text
    fi
    if [[ -z "$keywords" ]]; then
        echo "Enter keywords (space-separated):"
        read -r keywords
    fi

    # Save entry
    {
        echo "---"
        echo "Text: $text"
        echo "Keywords: $keywords"
    } >> "$BRAIN_FILE"

    echo -e "\e[32m[OK]\e[0m Entry saved."
}

print_entry() {
    local entry_text="$1"
    local entry_keywords="$2"

    echo -e "\e[1;33m------------------------\e[0m"
    echo -e "\e[36m$entry_text\e[0m"
    echo -e "\e[35mKeywords:\e[0m $entry_keywords"
}

search_entries() {
    local mode="or"
    local keywords=()

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == "and" || "$1" == "or" ]]; then
            mode="$1"
        else
            keywords+=("$1")
        fi
        shift
    done

    [[ ! -f "$BRAIN_FILE" ]] && echo "File $BRAIN_FILE not found." && exit 1

    local entry_text=""
    local entry_keywords=""
    local found=0

    while IFS= read -r line || [ -n "$line" ]; do
        # Start of new entry
        if [[ "$line" == "---" ]]; then
            # If we had a previous entry, process it
            if [[ -n "$entry_keywords" ]]; then
                local match_count=0
                for keyword in "${keywords[@]}"; do
                    if grep -q -w "$keyword" <<< "$entry_keywords"; then
                        ((match_count++))
                    fi
                done

                if [[ "$mode" == "and" && $match_count -eq ${#keywords[@]} ]] || \
                   [[ "$mode" == "or" && $match_count -gt 0 ]]; then
                    found=1
		    print_entry "$entry_text $entry_keywords"
                fi
            fi

            # Reset for new entry
            entry_text=""
            entry_keywords=""
        elif [[ "$line" =~ ^[[:space:]]*Text:[[:space:]]*(.*) ]]; then
            entry_text="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*Keywords:[[:space:]]*(.*) ]]; then
            entry_keywords="${BASH_REMATCH[1]}"
        fi
    done < "$BRAIN_FILE"

    # Process the last entry in the file
    if [[ -n "$entry_keywords" ]]; then
        local match_count=0
        for keyword in "${keywords[@]}"; do
            if grep -q -w "$keyword" <<< "$entry_keywords"; then
                ((match_count++))
            fi
        done

        if [[ "$mode" == "and" && $match_count -eq ${#keywords[@]} ]] || \
           [[ "$mode" == "or" && $match_count -gt 0 ]]; then
            found=1
            echo -e "\e[1;33m------------------------\e[0m"
            echo -e "\e[36m$entry_text\e[0m"
            echo -e "\e[35mKeywords:\e[0m $entry_keywords"
        fi
    fi

    [[ $found -eq 0 ]] && echo -e "\e[31mNo matching entry found.\e[0m"
}

show_info() {
    [[ ! -f "$BRAIN_FILE" ]] && echo "File $BRAIN_FILE not found." && exit 1

    count=$(grep -c "^Text:" "$BRAIN_FILE")
    echo "Brain file: $BRAIN_FILE"
    echo "Number of entries: $count"
}

print_all() {
    if [[ -f "$BRAIN_FILE" ]]; then
        entry_text=""
        entry_keywords=""
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" == Text:* ]]; then
                entry_text="${line#Text: }"
            elif [[ "$line" == Keywords:* ]]; then
                entry_keywords="${line#Keywords: }"
                print_entry "$entry_text" "$entry_keywords"
                entry_text=""
                entry_keywords=""
            fi
        done < "$BRAIN_FILE"
    else
        echo "No brain file found at $BRAIN_FILE"
    fi

}

command="$1"

if [[ -z "$command" ]]; then
    print_all
else    
    case "$1" in
	store)
            shift
            store_entry "$@"
            ;;
	search)
            shift
            search_entries "$@"
            ;;
	info)
            show_info
            ;;
	*)
            echo "Usage: brain [store|search|info]"
            ;;
    esac
fi

import sys
import re
import json
import os
import yara
import logging


class Banshee:
    """
    Banshee leaves all its strings unobfuscated.
    Just need to find the important info.
    """

    DISALLOWED_URLS = [
        'https://api.telegram.org/bot%@/',
        'https://freeipapi.com/api/json/',
        'https://api.ipify.org/?format=json'
    ]

    def __init__(self, path: str):
        if not path:
            raise ValueError("File path is required.")
        if not os.path.exists(path):
            raise FileNotFoundError(f"File {path} does not exist.")
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Path {path} is not a file.")

        self.file_path = path
        self.config = {'Malware': 'Banshee'}

        try:
            with open(self.file_path, 'rb') as file:
                self.file_data = file.read()
            if not self.file_data:
                raise ValueError(f"File data is empty {path}.")
        except PermissionError as e:
            raise PermissionError(f"Permission denied reading file {path}: {e}")
        except IOError as e:
            raise IOError(f"Failed to read file {path}: {e}")
        except Exception as e:
            raise Exception(f"Unexpected error reading file {path}: {e}")


    def _decode_safely(self, data: bytes) -> list[str]:
        """
        Safely decode binary data to strings.
        """
        try:
            return data.decode('utf-8', 'ignore').split('\x00')
        except UnicodeDecodeError as e:
            logging.error(f"Failed to decode file data: {e}")
            raise UnicodeDecodeError(f"Failed to decode file data: {e}")
        except Exception as e:
            logging.error(f"Unexpected error decoding data: {e}")
            raise RuntimeError(f"Unexpected error decoding data: {e}")

    def find_ip_address(self) -> bool:
        """
        Uses regex to find url. It's always an HTTP/HTTPS address.
        There are only a few other urls within the binary that are
        hardcoded and the same in all samples encountered so they simply get
        filtered out.
        """
        urls = []
        pattern = r'https?://[^\x00]+'

        try:
            strings = self._decode_safely(self.file_data)

            for string in strings:
                match = re.match(pattern, string)
                if match:
                    urls.append(match.string)

            if not urls:
                logging.warning("Warning: No URLs found.")
                return False

            valid_urls = [url for url in urls if not any(disallowed in url for disallowed in self.DISALLOWED_URLS)]

            if not valid_urls:
                logging.warning("Warning: No valid URLs found.")
                return False
            else:
                self.config['C2'] = valid_urls[0]
                return True
        except Exception as e:
            logging.error(f"Error finding IP address: {e}")
            return False


    def find_telegram(self) -> None:
        """
        Some but not all samples attempt to also send via Telegram
        along with to the C2. This uses regex to attempt to find
        the Telegram bot and chat IDs.
        """
        telegram_data = []
        bot_pattern = r'\d{10}\:'               # Simple 10 digit number followed by a ":". Should be the only string in here like this.
        chat_id_pattern = r'(-?)\d{10}$'        # 10 digit number only with nothing following it. Also the "-" is optional.

        try:
            strings = self._decode_safely(self.file_data)
            bot_match_found = False
            chat_match_found = False

            for string in strings:
                bot_match = re.match(bot_pattern, string)
                if bot_match and not bot_match_found:
                    self.config['Telegram Bot ID'] = bot_match.string
                    bot_match_found = True

                chat_match = re.match(chat_id_pattern, string)
                if chat_match and not chat_match_found:
                    self.config['Telegram Chat ID'] = chat_match.string
                    chat_match_found = True

                # If both found, break early
                if bot_match_found and chat_match_found:
                    break

            if not bot_match_found:
                logging.warning("Warning: No Telegram Bot ID found.")
            if not chat_match_found:
                logging.warning("Warning: No Telegram Chat ID found.")
        except Exception as e:
            logging.error(f"Error finding Telegram identifiers: {e}")

    def find_build_id(self) -> None:
        """
        The Build ID is a 30-character string and usually found near BUILD_ID.
        Use YARA to get us close then look forward and backward and regex
        to find the exact string.
        """
        offsets = []
        possible_build_ids = set()

        # Find the pertinent strings where the Build ID value is usually next to
        yara_rule = """
                    rule build_id 
                    { 
                         strings: 
                            $s1 = "BUILD_ID" fullword ascii 
                            $s2 = "Using BUILD_ID: %@" fullword ascii 
                         condition: 
                            any of them 
                    }
                    """
        try:
            compiled_rule = yara.compile(source=yara_rule)
            matches = compiled_rule.match(data=self.file_data)
            if matches:
                for string in matches[0].strings:
                    # Get offset for any match
                    for instance in string.instances:
                        offsets.append(instance.offset)
        except Exception as yara_error:
            logging.error(f"YARA error: {yara_error}")
            return

        # Once offsets are collected we can look at the data around each to find a valid Build ID value.
        for offset in offsets:
            # Look before and after the offset for potential Build IDs
            for range_offset in [
                (offset, offset + 100),
                (max(0, offset - 100), offset)
            ]:
                try:
                    data_chunk = self.file_data[range_offset[0]:range_offset[1]]
                    strings_chunk = self._decode_safely(data_chunk)

                    for string in strings_chunk:
                        if len(string) == 30:
                            test_pattern = r'^[A-Za-z0-9]{30}$'
                            match = re.match(test_pattern, string)
                            if match:
                                possible_build_ids.add(match.string)
                except Exception as e:
                    logging.error(f"Error processing offset {offset}: {e}")

        if possible_build_ids:
            self.config['Build ID'] = list(possible_build_ids)[0]       # Should only be one found
            if len(possible_build_ids) > 1:
                logging.warning("Warning: Multiple possible Build IDs found.")
        else:
            logging.warning("Warning: No Build ID found.")


    def extract(self) -> dict[str, any]:
        """
        Extract configuration information from the binary.
        """
        try:
            self.find_ip_address()
        except Exception as e:
            logging.error(f"Error in find_ip_address: {e}")

        try:
            self.find_telegram()
        except Exception as e:
            logging.error(f"Error in find_telegram: {e}")

        try:
            self.find_build_id()
        except Exception as e:
            logging.error(f"Error in find_build_id: {e}")

        return self.config



if __name__ == "__main__":
    """
    Main entry point
    """
    try:
        file = sys.argv[1]

        # Extract configuration
        banshee = Banshee(file)
        config = banshee.extract()

        # Output
        print(json.dumps(config, indent=4))

    except Exception as e:
        logging.error(f"Error: {e}")
        exit(1)

import argparse
import logging
from abc import ABC, abstractmethod
from typing import Dict, List

import patchright
from patchright.sync_api import sync_playwright
from playwright_stealth import stealth_sync

from vfs_appointment_bot.utils.config_reader import get_config_value
from vfs_appointment_bot.notification.notification_client_factory import (
    get_notification_client,
)


class LoginError(Exception):
    """Exception raised when login fails."""


class VfsBot(ABC):
    """
    Abstract base class for VfsBot

    Provides common functionalities like login, pre-login steps, appointment checking, and notification.
    Subclasses are responsible for implementing country-specific login and appointment checking logic.
    """

    def __init__(self):
        """
        Initializes a VfsBot instance for a specific country.

        """
        self.source_country_code = None
        self.destination_country_code = None
        self.appointment_param_keys: List[str] = []

    def run(self, args: argparse.Namespace = None) -> bool:
        """
        Starts the VFS bot for appointment checking and notification.

        This method reads configuration values, performs login, checks for
        appointments based on provided arguments, and sends notifications if
        appointments are found.

        Args:
            args (argparse.Namespace, optional): Namespace object containing parsed
                command-line arguments. Defaults to None.

        Returns:
            bool: True if appointments were found, False otherwise.
        """

        logging.info(
            f"Starting VFS Bot for {self.source_country_code.upper()}-{self.destination_country_code.upper()}"
        )

        # Configuration values
        try:
            browser_type = get_config_value("browser", "type", "firefox")
            headless_mode = get_config_value("browser", "headless", "True")
            url_key = self.source_country_code + "-" + self.destination_country_code
            vfs_url = get_config_value("vfs-url", url_key)
        except KeyError as e:
            logging.error(f"Missing configuration value: {e}")
            return

        email_id = get_config_value("vfs-credential", "email")
        password = get_config_value("vfs-credential", "password")

        appointment_params = self.get_appointment_params(args)

        cookies = [
            {"name": key, "value": value, "domain": ".visa.vfsglobal.com", "path": "/"}
            for key, value in {
                "dtCookie": "-14$RUGP8M9NP475U718E5U8292886R09BQ9",
                "rxVisitor": "1736456320917E62D6AKP2MMTR1MCTBA27G8A1OU71Q6G",
                "rxvt": "1737141112873|1737139312873",
                "dtPC": "-14$139312869_399h1vHSHHWARBFMEPSDKRJUCWTIVRFAPOPCKB-0",
                "OptanonAlertBoxClosed": "2025-01-17T18:42:00.446Z",
                "OptanonConsent": "isGpcEnabled=0&datestamp=Fri+Jan+17+2025+21%3A42%3A00...",
                "__cf_bm": "pzYGIf9LbEO_FYNKZ5x3NTXyxILU1_pWZYUNOY4iv7Q...",
                "_cfuvid": "m9ZaOMC.THjGAQr0InPNK1hm8gYxTMlWx_WZ3gn7d4Y...",
                "cf_clearance": "TtPWu0ZquPB.iVOoRLws2wa3jEyI.xDF6bAzJgRRbKM...",
            }.items()
        ]

        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.6,en;q=0.5",
            "cache-control": "max-age=0",
            "dnt": "1",
            "priority": "u=0, i",
            "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        }

        # Launch browser and perform actions
        with sync_playwright() as p:
            browser = getattr(p, browser_type).launch(
                headless=headless_mode in ("True", "true")
            )
            context = browser.new_context(extra_http_headers=headers)

            page = browser.new_page()
            stealth_sync(page)

            page.goto(vfs_url)
            self.pre_login_steps(page)

            try:
                self.login(page, email_id, password)
                logging.info("Logged in successfully")
            except Exception:
                browser.close()
                raise LoginError(
                    "\033[1;31mLogin failed. "
                    + "Please verify your username and password by logging in to the browser and try again.\033[0m"
                )

            logging.info(f"Checking appointments for {appointment_params}")
            appointment_found = False
            try:
                dates = self.check_for_appontment(page, appointment_params)
                if dates:
                    # Log successful appointment finding
                    logging.info(
                        f"\033[1;32mFound appointments on: {', '.join(dates)} \033[0m"
                    )
                    self.notify_appointment(appointment_params, dates)
                    appointment_found = True
                else:
                    # Log no appointments found
                    logging.info(
                        "\033[1;33mNo appointments found for the specified criteria.\033[0m"
                    )
            except Exception as e:
                logging.error(f"Appointment check failed: {e}")
            browser.close()
            return appointment_found

    def get_appointment_params(self, args: argparse.Namespace) -> Dict[str, str]:
        """
        Collects appointment parameters from command-line arguments or user input.

        This method iterates through pre-defined `appointment_param_keys` (replace
        with relevant keys) and retrieves values either from provided arguments
        or prompts the user for input if values are missing.

        Args:
            args (argparse.Namespace): Namespace object containing parsed command-line arguments.

        Returns:
            Dict[str, str]: A dictionary containing appointment parameters.
        """
        appointment_params = {}
        for key in self.appointment_param_keys:
            if (
                getattr(args, "appointment_params") is not None
                and args.appointment_params[key] is not None
            ):
                appointment_params[key] = args.appointment_params[key]
            else:
                key_name = key.replace("_", " ")
                appointment_params[key] = input(f"Enter the {key_name}: ")
        return appointment_params

    def notify_appointment(self, appointment_params: Dict[str, str], dates: List[str]):
        """
        Sends appointment dates notification to the user.

        This method is responsible for notifying the appointment dates to the user configured channels

        Args:
            dates (List[str]): A list of appointment dates.
            appointment_params (Dict[str, str]): A dictionary containing appointment search criteria.
        """
        message = f"Found appointment(s) for {', '.join(appointment_params.values())} on {', '.join(dates)}"
        channels = get_config_value("notification", "channels")
        if len(channels) == 0:
            logging.warning(
                "No notification channels configured. Skipping notification."
            )
            return

        for channel in channels.split(","):
            client = get_notification_client(channel)
            try:
                client.send_notification(message)
            except Exception:
                logging.error(f"Failed to send {channel} notification")

    @abstractmethod
    def login(
        self, page: patchright.sync_api.Page, email_id: str, password: str
    ) -> None:
        """
        Performs login steps specific to the VFS website for the bot's country.

        This abstract method needs to be implemented by subclasses to handle
        country-specific login procedures (e.g., filling login form elements, handling
        CAPTCHAs). It should interact with the Playwright `page` object to achieve
        login functionality.

        Args:
            page (playwright.sync_api.Page): The Playwright page object used for browser interaction.
            email_id (str): The user's email address for VFS login.
            password (str): The user's password for VFS login.

        Raises:
            Exception: If login fails due to unexpected errors.
        """
        raise NotImplementedError("Subclasses must implement login logic")

    @abstractmethod
    def pre_login_steps(self, page: patchright.sync_api.Page) -> None:
        """
        Performs any pre-login steps required by the VFS website for the bot's country.

        This abstract method allows subclasses to implement country-specific actions
        that need to be done before login (e.g., cookie acceptance, language selection).
        It should interact with the Playwright `page` object to perform these actions.

        Args:
            page (playwright.sync_api.Page): The Playwright page object used for browser interaction.
        """

    @abstractmethod
    def check_for_appontment(
        self, page: patchright.sync_api.Page, appointment_params: Dict[str, str]
    ) -> List[str]:
        """
        Checks for appointments based on provided parameters on the VFS website.

        This abstract method needs to be implemented by subclasses to interact with
        the VFS website and search for appointments based on the given `appointment_params`
        dictionary. It should use the Playwright `page` object to navigate the website
        and extract appointment dates.

        Args:
            page (playwright.sync_api.Page): The Playwright page object used for browser interaction.
            appointment_params (Dict[str, str]): A dictionary containing appointment search criteria.

        Returns:
            List[str]: A list of available appointment dates (empty list if none found).
        """
        raise NotImplementedError(
            "Subclasses must implement appointment checking logic"
        )

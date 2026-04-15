import logging

import azure.functions as func

from cert_renewal import RenewalManager, load_settings


app = func.FunctionApp()


@app.timer_trigger(schedule="0 0 2 * * *", arg_name="timer", run_on_startup=False, use_monitor=True)
def renew_certificate(timer: func.TimerRequest) -> None:
    if timer.past_due:
        logging.warning("定时任务延迟触发 / Timer trigger is running past due")

    settings = load_settings()
    manager = RenewalManager(settings)
    manager.run()

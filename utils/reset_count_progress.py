from data.config import completed_tasks, remaining_tasks


def set_progress_to_zero():
    remaining_tasks[0] = 0
    completed_tasks[0] = 0
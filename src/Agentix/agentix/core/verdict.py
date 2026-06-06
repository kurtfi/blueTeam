def parse_verdict(final_answer: str | None) -> str:
    """
    Parses the final session verdict (TRUE_POSITIVE, FALSE_POSITIVE, UNDETERMINED)
    from the LLM's final answer string based on verdict tags.
    """
    if not final_answer:
        return "UNDETERMINED"
    
    final_answer_upper = final_answer.upper()
    if "VERDICT: TRUE_POSITIVE" in final_answer_upper:
        return "TRUE_POSITIVE"
    elif "VERDICT: FALSE_POSITIVE" in final_answer_upper:
        return "FALSE_POSITIVE"
    elif "VERDICT: UNDETERMINED" in final_answer_upper:
        return "UNDETERMINED"
        
    return "UNDETERMINED"

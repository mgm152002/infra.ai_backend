from app.core.llm import call_llm
from app.core.database import supabase
import datetime

class RCAService:
    def __init__(self):
        pass

    def generate_rca(self, incident_number: str):
        """
        Generates a Root Cause Analysis report for a given incident.
        """
        # 1. Fetch incident details
        try:
            incident_response = supabase.table("Incidents").select("*").eq("inc_number", incident_number).execute()
            if not incident_response.data:
                return {"error": "Incident not found"}
            incident = incident_response.data[0]
        except Exception as e:
            return {"error": f"Failed to fetch incident: {str(e)}"}

        # 2. Fetch resolution results/chat logs
        try:
            results_response = supabase.table("Results").select("*").eq("inc_number", incident_number).order("created_at").execute()
            results = results_response.data if results_response.data else []
            
            # Combine results into a context string
            context_str = f"Incident Details:\n"
            context_str += f"- ID: {incident.get('inc_number')}\n"
            context_str += f"- Short Description: {incident.get('short_description', 'N/A')}\n"
            context_str += f"- Description: {incident.get('description', 'N/A')}\n"
            context_str += f"- State: {incident.get('state', 'Unknown')}\n"
            context_str += f"- Created At: {incident.get('created_at', 'Unknown')}\n\n"
            
            context_str += "Investigation & Resolution Timeline:\n"
            for res in results:
                timestamp = res.get('created_at', '')
                description = res.get('description', '')
                context_str += f"[{timestamp}] {description}\n"
                
        except Exception as e:
            return {"error": f"Failed to fetch results: {str(e)}"}

        # 3. Call LLM to generate RCA
        prompt = f"""
        You are an expert Site Reliability Engineer (SRE) and Incident Manager.
        Your task is to generate a comprehensive Root Cause Analysis (RCA) report for the following incident, adhering to ITIL best practices.
        
        Input Context:
        {context_str}
        
        Please generate the RCA report in strictly formatted Markdown. Include the following sections:
        
        # Root Cause Analysis: {incident.get('inc_number')} - {incident.get('short_description')}
        
        ## 1. Executive Summary
        A brief overview of the incident, its impact, and how it was resolved. Keep this high-level for leadership.
        
        ## 2. Detailed Timeline
        Construct a chronological timeline of events based on the provided logs, including detection, diagnosis, and resolution steps. Resulting timestamp format should be readable.
        
        ## 3. Root Cause (The "Why")
        Perform a "5 Whys" analysis if enough context is available, or explain the technical root cause. Distinguish between the direct cause and contributing factors.
        
        ## 4. Resolution & Recovery
        Describe the specific steps taken to fix the issue and restore service.
        
        ## 5. Corrective & Preventive Measures
        List specific action items to prevent recurrence. Categorize them if possible (e.g., Code Fix, Configuration Change, Process Improvement, Monitoring).
        
        Do not include any conversational filler. Output ONLY the Markdown report.
        """
        
        try:
            rca_content = call_llm(prompt)
        except Exception as e:
             return {"error": f"LLM generation failed: {str(e)}"}

        # 4. Save RCA report to database
        try:
            # Check if RCA already exists, update if so
            existing = supabase.table("rca_reports").select("id").eq("incident_id", incident_number).execute()
            
            if existing.data:
                supabase.table("rca_reports").update({
                    "report_content": rca_content,
                    "created_at": datetime.datetime.now().isoformat(),
                    "generated_by": "system"
                }).eq("incident_id", incident_number).execute()
            else:
                supabase.table("rca_reports").insert({
                    "incident_id": incident_number,
                    "report_content": rca_content,
                    "created_at": datetime.datetime.now().isoformat(),
                    "generated_by": "system"
                }).execute()
                
        except Exception as e:
            return {"error": f"Failed to save RCA report: {str(e)}", "content": rca_content}

        return {"success": True, "rca_content": rca_content}
    
    def get_rca(self, incident_number: str):
        try:
            response = supabase.table("rca_reports").select("*").eq("incident_id", incident_number).execute()
            if response.data:
                return response.data[0]
            return None
        except Exception as e:
             return {"error": f"Failed to fetch RCA: {str(e)}"}

rca_service = RCAService()

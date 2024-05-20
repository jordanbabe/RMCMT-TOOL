import json

from decimal import Decimal
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.generic import View
from qa.models import (
    Question,
    Answer,
    UserAttempt
)
from .models import About, Assets, RiskScale, RiskRegister
from .utils import validate_and_import_csv, export_assets_data
from .OpenCVE.datas import OPENCVEDB_DATA

class DashView(View):
    def get(self, request, *args, **kwargs):
        context = {"title":"dash"}
        return render(request, "dashboard/dash.html", context)

class DashboardView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        user_attempt = UserAttempt.objects.filter(
            user = request.user,
            all_question_attempted = True,
            question__question_type__type="Type A"
        )
        context = {"title":"dashboard"}
        if user_attempt.exists():
            earned_points = Decimal('0.0')
            for attempted in user_attempt:
                earned_points += attempted.points_earned if attempted.points_earned else Decimal('0.0')
            context["earned_points"] = earned_points
        else:
            questions = Question.objects.filter(question_type__type="Type A")
            questions_with_answers = []
            for question in questions:
                answers = question.answer.all()
                if answers:
                    questions_with_answers.append({'question': question, 'answers': answers})
            context["questions_with_answers"] = questions_with_answers
        return render(request, "dashboard/risk_assessment.html", context)
    

class RiskAssessmentAttemptView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        # Get the list of question-answer pairs from request.POST data
        qa_dict = {}
        selected_answers_ids = request.POST.getlist('answers')
        selected_answers = Answer.objects.filter(id__in=selected_answers_ids)
        for answer in selected_answers:
            question_id = answer.question.id
            if question_id not in qa_dict:
                qa_dict[question_id] = {"question": question_id, "answers": [], "points":[]}
            qa_dict[question_id]["answers"].append(answer.id)
            qa_dict[question_id]["points"].append(answer.points)

        qa = list(qa_dict.values())

        for pair in qa:
            user_attempt = UserAttempt.objects.create(
                user=request.user,
                question=Question.objects.get(id=pair["question"]),
                points_earned=sum(pair["points"]),
                all_question_attempted=True
            )
            user_attempt.selected_answer.set(pair["answers"])
            user_attempt.save()
                    
        return redirect("dashboard:dashboard")



class CommonThreatView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        context = {"title":"common_threat"}
        return render(request, "dashboard/common_threat.html", context)



# def search_product_vendor(data, product, vendor):
#     results = []
#     for data in data:
#         for container in data.get("containers", {}).values():
#             for affected in container.get("affected", []):
#                 if affected.get("product", "").lower() == product.lower() and affected.get("vendor", "").lower() == vendor.lower():
#                     results.append(container)
#     return results

def search_product_vendor(data, product, vendor):
    results = []
    for data_item in data:
        for container in data_item.get("containers", {}).values():
            for affected in container.get("affected", []):
                if affected.get("product", "").lower() == product.lower() and \
                        affected.get("vendor", "").lower() == vendor.lower():
                    result = {
                        "cveId": data_item.get("cveMetadata", {}).get("cveId"),
                        "versions": affected.get("versions"),
                        "descriptions": container.get("problemTypes"),
                    }
                    results.append(result)
    return results


class AssetsView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        qs = Assets.objects.filter(is_deleted=False, user=request.user).values()
        for asset in qs:
            # results = search_product_vendor(OPENCVEDB_DATA, "Apache Tomcat", "Apache Software Foundation")
            results = search_product_vendor(OPENCVEDB_DATA, asset.get("os"), asset.get("software"))
            formatted_results = []
            for result in results:
                formatted_result = json.dumps(result, indent=4)  # Indent for better readability
                formatted_results.append(formatted_result)
            asset["open_cve_data"] = formatted_results

            # asset.update({"open_cve_data":res})

        context = {"datas":qs, "title":"assets"}
        return render(request, "dashboard/assets.html", context)
    
class TrainingsView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        context = {"title":"trainings"}
        return render(request, "dashboard/trainings.html", context)
    
class ComplianceView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        context = {"title":"compilance"}
        questions = Question.objects.filter(question_type__type="Type B")
        questions_with_answers = []
        for question in questions:
            answers = question.answer.all()
            if answers:
                questions_with_answers.append({'question': question, 'answers': answers})
        context["questions_with_answers"] = questions_with_answers
        return render(request, "dashboard/compilance.html", context)
    
class AboutView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        qs = About.objects.filter(is_deleted=False)
        context = {"about":qs, "title":"about"}
        return render(request, "dashboard/about.html", context)
    

class CompilanceQAAttemptView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        # Get the list of question-answer pairs from request.POST data
        qa_dict = {}
        selected_answers_ids = request.POST.getlist('answers')
        selected_answers = Answer.objects.filter(id__in=selected_answers_ids)
        total_points = 0
        for answer in selected_answers:
            question_id = answer.question.id
            if question_id not in qa_dict:
                qa_dict[question_id] = {"question": question_id, "answers": [], "points":[]}
            qa_dict[question_id]["answers"].append(answer.id)
            qa_dict[question_id]["points"].append(answer.points)
            total_points += answer.points

        qa = list(qa_dict.values())
        # print("l115", qa)

        messages.success(request, f"Your attempt was successful. Total points: {total_points}")

        return redirect("dashboard:compilance")
    

class AssetsUploadView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        if 'file' not in request.FILES:
            messages.error(request, "Please select a file to upload")
            return redirect("dashboard:assets")

        file = request.FILES['file']

        file_name = file.name
        file_extension = file_name.split(".")[-1]
        if 'csv' not in file_extension:
            messages.error(request, "Please upload in CSV format.")
            return redirect("dashboard:assets")
        
        try:
            data = validate_and_import_csv(file, user=request.user)
            messages.success(request, "Data imported successfully")
        except Exception as e:
            messages.error(request, str(e))

        return redirect("dashboard:assets")
    
class ExportAssetsDataView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        response = export_assets_data(request)
        return response
    


class RiskRegisterView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        risk_register = RiskRegister.objects.filter(user=request.user, is_deleted=False).values()
        
        for item in risk_register:
            # Calculate PRIORITY LEVEL
            item['priority_level'] = item['impact_level'] * item['probability_level']
            
            # Fetch color code from RiskScore model
            risk_score = RiskScale.objects.filter(number=item['priority_level']).first()
            if risk_score:
                item['color_code'] = risk_score.color_code
            else:
                item['color_code'] = "#FFFFFF"
        
        context={"title":"risk_register", "risk_registers": risk_register}
        return render(request, "dashboard/risk-register.html", context)
    

class RiskRegisterCreateView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        data = request.POST
        risk_desc = data.get("riskDesc")
        impactDesc = data.get("impactDesc")
        impactLevel = data.get("impactLevel")
        probalityLevel = data.get("probalityLevel")
        migrationsNotes = data.get("migrationsNotes")
        owner = data.get("owner")

        level = ['1','2','3','4','5']

        valid_impact_level = any(lvl in level for lvl in impactLevel)
        valid_probality_level = any(lvl in level for lvl in probalityLevel)
        
        if not (valid_impact_level and valid_probality_level):
            messages.error(request, "Please select a valid impact level and probability level")
            return redirect("dashboard:risk_register")

        risk_register = RiskRegister(
            user=request.user,
            risk_description=risk_desc,
            impact_description=impactDesc,
            impact_level=impactLevel,
            probability_level=probalityLevel,
            migrations_notes=migrationsNotes,
            owner=owner,
        )
        risk_register.save()
        messages.success(request, "Success to create risk register.")
        return redirect("dashboard:risk_register")
    
class RiskRegisterUpdateView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        try:
            instance = RiskRegister.objects.get(id=kwargs.get('pk'))
            
            data = request.POST
            instance.risk_description = data.get("riskDesc")
            instance.impact_description = data.get("impactDesc")
            instance.impact_level = data.get("impactLevel")
            instance.probability_level = data.get("probalityLevel")
            instance.migrations_notes = data.get("migrationsNotes")
            instance.owner = data.get("owner")
            instance.save()
            
            messages.success(request, "Successfully updated risk register.")
        except ObjectDoesNotExist:
            messages.error(request, "Risk register not found.")
        
        return redirect("dashboard:risk_register")
        
        

class RiskRegisterDeleteView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        try:
            instance = RiskRegister.objects.get(id=kwargs.get('pk'))
            instance.is_deleted = True
            instance.save()

            messages.success(request, "Successfully deleted risk register.")
        except ObjectDoesNotExist:
            messages.error(request, "Risk register not found.")
        
        return redirect("dashboard:risk_register")
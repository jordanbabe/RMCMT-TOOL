import pandas as pd
import ipaddress
from django.http import HttpResponse
from .models import Assets

def validate_and_import_csv(file, *args, **kwargs):
    user = kwargs.pop("user")
    df = pd.read_csv(file)
    
    # Validate required columns
    required_columns = ["Host Name", "OS", "OS Version"]
    missing_columns = set(required_columns) - set(df.columns)
    if missing_columns:
        raise ValueError(f"Missing required columns: {', '.join(missing_columns)}")

    # Validate required values
    missing_values = df[df["Host Name"].isnull() | df["OS"].isnull()]
    if not missing_values.empty:
        raise ValueError(f"Missing required values for Host Name or OS")

    # Validate IP addresses
    # for ip_address in df["IP Address"]:
    #     try:
    #         ipaddress.ip_address(ip_address)
    #     except ValueError:
    #         raise ValueError(f"Invalid IP address format: {ip_address}")


    # os_versions = {
    #         "Windows": ["XP", "7", "8", "10"],
    #         "Linux": ["Ubuntu", "Fedora", "CentOS", "Debian"],
    #         "macOS": ["Catalina", "Big Sur", "Mojave", "High Sierra"],
    #     }
    
    # for _, row in df.iterrows():
    #     os = row["OS"]
    #     version = row["Software"]
    #     if os not in os_versions:
    #         raise ValueError(f"Unknown operating system: {os}")
    #     if version not in os_versions[os]:
    #         raise ValueError(f"Unsupported software for {os}: {version}")
        

    # Save validated data to the model
    asset_objects = [
        Assets(
            user=user,
            host_name=row["Host Name"],
            os=row["OS"],
            software=row["OS Version"],
            other={},
        )
        for _, row in df.iterrows()
    ]

    # Bulk create the objects
    Assets.objects.bulk_create(asset_objects)

    return asset_objects



def export_assets_data(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="assets_data.csv"'

    assets = Assets.objects.all()
    data = {
        'Host Name': [asset.host_name for asset in assets],
        'OS': [asset.os for asset in assets],
        'OS Version': [asset.software for asset in assets],
    }

    df = pd.DataFrame(data)
    df.to_csv(response, index=False)

    return response


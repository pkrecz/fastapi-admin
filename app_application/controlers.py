from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from app_admin.decorators import permission_required


router = APIRouter()


@router.get('/', status_code=status.HTTP_200_OK)
@permission_required(required_permission="example_permission")
async def root():
    return JSONResponse(content={'message': 'Welcome in application.'}, status_code=status.HTTP_200_OK)

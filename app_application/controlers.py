from fastapi import APIRouter, status
from fastapi.responses import JSONResponse


router = APIRouter()


@router.get('/', status_code=status.HTTP_200_OK)
async def root():
    return JSONResponse(content={'message': 'Welcome in application.'}, status_code=status.HTTP_200_OK)
